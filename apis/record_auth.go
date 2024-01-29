package apis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"html/template"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jfmow/pocketbase-custom/core"
	"github.com/jfmow/pocketbase-custom/daos"
	"github.com/jfmow/pocketbase-custom/forms"
	"github.com/jfmow/pocketbase-custom/models"
	"github.com/jfmow/pocketbase-custom/resolvers"
	"github.com/jfmow/pocketbase-custom/tools/auth"
	"github.com/jfmow/pocketbase-custom/tools/mailer"
	"github.com/jfmow/pocketbase-custom/tools/routine"
	"github.com/jfmow/pocketbase-custom/tools/search"
	"github.com/jfmow/pocketbase-custom/tools/security"
	"github.com/jfmow/pocketbase-custom/tools/subscriptions"
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/dbx"
	"golang.org/x/oauth2"
)

// bindRecordAuthApi registers the auth record api endpoints and
// the corresponding handlers.
func bindRecordAuthApi(app core.App, rg *echo.Group) {
	api := recordAuthApi{app: app}

	// global oauth2 subscription redirect handler
	rg.GET("/oauth2-redirect", api.oauth2SubscriptionRedirect)

	// common collection record related routes
	subGroup := rg.Group(
		"/collections/:collection",
		ActivityLogger(app),
		LoadCollectionContext(app, models.CollectionTypeAuth),
	)
	subGroup.GET("/auth-methods", api.authMethods)
	subGroup.POST("/auth-refresh", api.authRefresh, RequireSameContextRecordAuth())
	subGroup.POST("/auth-with-oauth2", api.authWithOAuth2)
	subGroup.POST("/auth-with-password", api.authWithPassword)
	subGroup.POST("/request-email-token", api.requestEmailAuthToken)
	subGroup.POST("/auth-with-email-token", api.authWithEmailJWT)
	subGroup.POST("/toggle-email-token", api.toggleEmailAuthJWT)
	subGroup.POST("/request-password-reset", api.requestPasswordReset)
	subGroup.POST("/confirm-password-reset", api.confirmPasswordReset)
	subGroup.POST("/request-verification", api.requestVerification)
	subGroup.POST("/confirm-verification", api.confirmVerification)
	subGroup.POST("/request-email-change", api.requestEmailChange, RequireSameContextRecordAuth())
	subGroup.POST("/confirm-email-change", api.confirmEmailChange)
	subGroup.GET("/records/:id/external-auths", api.listExternalAuths, RequireAdminOrOwnerAuth("id"))
	subGroup.DELETE("/records/:id/external-auths/:provider", api.unlinkExternalAuth, RequireAdminOrOwnerAuth("id"))

	exeDir, _ := os.Getwd()
	htmlFile, err := os.ReadFile(filepath.Join(exeDir, "/emails", "/emailAuth.html"))
	if err != nil {
		panic(err)
	}

	// Convert the HTML file content to a string
	htmlString := string(htmlFile)
	template, err := template.New("emailAuthTemplate").Parse(htmlString)
	if err != nil {
		panic(err)
	}
	emailTemplate = template
}

type recordAuthApi struct {
	app core.App
}

func (api *recordAuthApi) authRefresh(c echo.Context) error {
	record, _ := c.Get(ContextAuthRecordKey).(*models.Record)
	if record == nil {
		return NewNotFoundError("Missing auth record context.", nil)
	}

	event := new(core.RecordAuthRefreshEvent)
	event.HttpContext = c
	event.Collection = record.Collection()
	event.Record = record

	return api.app.OnRecordBeforeAuthRefreshRequest().Trigger(event, func(e *core.RecordAuthRefreshEvent) error {
		return api.app.OnRecordAfterAuthRefreshRequest().Trigger(event, func(e *core.RecordAuthRefreshEvent) error {
			return RecordAuthResponse(api.app, e.HttpContext, e.Record, nil)
		})
	})
}

type providerInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	AuthUrl     string `json:"authUrl"`
	// technically could be omitted if the provider doesn't support PKCE,
	// but to avoid breaking existing typed clients we'll return them as empty string
	CodeVerifier        string `json:"codeVerifier"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
}

func (api *recordAuthApi) authMethods(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	authOptions := collection.AuthOptions()

	result := struct {
		AuthProviders    []providerInfo `json:"authProviders"`
		UsernamePassword bool           `json:"usernamePassword"`
		EmailPassword    bool           `json:"emailPassword"`
		OnlyVerified     bool           `json:"onlyVerified"`
	}{
		UsernamePassword: authOptions.AllowUsernameAuth,
		EmailPassword:    authOptions.AllowEmailAuth,
		OnlyVerified:     authOptions.OnlyVerified,
		AuthProviders:    []providerInfo{},
	}

	if !authOptions.AllowOAuth2Auth {
		return c.JSON(http.StatusOK, result)
	}

	nameConfigMap := api.app.Settings().NamedAuthProviderConfigs()
	for name, config := range nameConfigMap {
		if !config.Enabled {
			continue
		}

		provider, err := auth.NewProviderByName(name)
		if err != nil {
			api.app.Logger().Debug("Missing or invalid provier name", slog.String("name", name))
			continue // skip provider
		}

		if err := config.SetupProvider(provider); err != nil {
			api.app.Logger().Debug(
				"Failed to setup provider",
				slog.String("name", name),
				slog.String("error", err.Error()),
			)
			continue // skip provider
		}

		info := providerInfo{
			Name:        name,
			DisplayName: provider.DisplayName(),
			State:       security.RandomString(30),
		}

		if info.DisplayName == "" {
			info.DisplayName = name
		}

		urlOpts := []oauth2.AuthCodeOption{}

		// custom providers url options
		switch name {
		case auth.NameApple:
			// see https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms#3332113
			urlOpts = append(urlOpts, oauth2.SetAuthURLParam("response_mode", "query"))
		}

		if provider.PKCE() {
			info.CodeVerifier = security.RandomString(43)
			info.CodeChallenge = security.S256Challenge(info.CodeVerifier)
			info.CodeChallengeMethod = "S256"
			urlOpts = append(urlOpts,
				oauth2.SetAuthURLParam("code_challenge", info.CodeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", info.CodeChallengeMethod),
			)
		}

		info.AuthUrl = provider.BuildAuthUrl(
			info.State,
			urlOpts...,
		) + "&redirect_uri=" // empty redirect_uri so that users can append their redirect url

		result.AuthProviders = append(result.AuthProviders, info)
	}

	// sort providers
	sort.SliceStable(result.AuthProviders, func(i, j int) bool {
		return result.AuthProviders[i].Name < result.AuthProviders[j].Name
	})

	return c.JSON(http.StatusOK, result)
}

func (api *recordAuthApi) authWithOAuth2(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	if !collection.AuthOptions().AllowOAuth2Auth {
		return NewBadRequestError("The collection is not configured to allow OAuth2 authentication.", nil)
	}

	var fallbackAuthRecord *models.Record

	loggedAuthRecord, _ := c.Get(ContextAuthRecordKey).(*models.Record)
	if loggedAuthRecord != nil && loggedAuthRecord.Collection().Id == collection.Id {
		fallbackAuthRecord = loggedAuthRecord
	}

	form := forms.NewRecordOAuth2Login(api.app, collection, fallbackAuthRecord)
	if readErr := c.Bind(form); readErr != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", readErr)
	}

	event := new(core.RecordAuthWithOAuth2Event)
	event.HttpContext = c
	event.Collection = collection
	event.ProviderName = form.Provider
	event.IsNewRecord = false

	form.SetBeforeNewRecordCreateFunc(func(createForm *forms.RecordUpsert, authRecord *models.Record, authUser *auth.AuthUser) error {
		return createForm.DrySubmit(func(txDao *daos.Dao) error {
			event.IsNewRecord = true
			// clone the current request data and assign the form create data as its body data
			requestInfo := *RequestInfo(c)
			requestInfo.Data = form.CreateData

			createRuleFunc := func(q *dbx.SelectQuery) error {
				admin, _ := c.Get(ContextAdminKey).(*models.Admin)
				if admin != nil {
					return nil // either admin or the rule is empty
				}

				if collection.CreateRule == nil {
					return errors.New("Only admins can create new accounts with OAuth2")
				}

				if *collection.CreateRule != "" {
					resolver := resolvers.NewRecordFieldResolver(txDao, collection, &requestInfo, true)
					expr, err := search.FilterData(*collection.CreateRule).BuildExpr(resolver)
					if err != nil {
						return err
					}
					resolver.UpdateQuery(q)
					q.AndWhere(expr)
				}

				return nil
			}

			if _, err := txDao.FindRecordById(collection.Id, createForm.Id, createRuleFunc); err != nil {
				return fmt.Errorf("Failed create rule constraint: %w", err)
			}

			return nil
		})
	})

	_, _, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*forms.RecordOAuth2LoginData]) forms.InterceptorNextFunc[*forms.RecordOAuth2LoginData] {
		return func(data *forms.RecordOAuth2LoginData) error {
			event.Record = data.Record
			event.OAuth2User = data.OAuth2User
			event.ProviderClient = data.ProviderClient

			return api.app.OnRecordBeforeAuthWithOAuth2Request().Trigger(event, func(e *core.RecordAuthWithOAuth2Event) error {
				data.Record = e.Record
				data.OAuth2User = e.OAuth2User

				if err := next(data); err != nil {
					return NewBadRequestError("Failed to authenticate.", err)
				}

				e.Record = data.Record
				e.OAuth2User = data.OAuth2User

				meta := struct {
					*auth.AuthUser
					IsNew bool `json:"isNew"`
				}{
					AuthUser: e.OAuth2User,
					IsNew:    event.IsNewRecord,
				}

				return api.app.OnRecordAfterAuthWithOAuth2Request().Trigger(event, func(e *core.RecordAuthWithOAuth2Event) error {
					return RecordAuthResponse(api.app, e.HttpContext, e.Record, meta)
				})
			})
		}
	})

	return submitErr
}

func (api *recordAuthApi) authWithPassword(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	form := forms.NewRecordPasswordLogin(api.app, collection)
	if readErr := c.Bind(form); readErr != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", readErr)
	}

	event := new(core.RecordAuthWithPasswordEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Password = form.Password
	event.Identity = form.Identity

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeAuthWithPasswordRequest().Trigger(event, func(e *core.RecordAuthWithPasswordEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to authenticate.", err)
				}

				return api.app.OnRecordAfterAuthWithPasswordRequest().Trigger(event, func(e *core.RecordAuthWithPasswordEvent) error {
					return RecordAuthResponse(api.app, e.HttpContext, e.Record, nil)
				})
			})
		}
	})

	return submitErr
}

//-----------

var (
	mapsMutex           sync.Mutex
	emailMutexMapLock   sync.Mutex
	emailMutexMap       = make(map[string]*sync.Mutex)
	emailLastRequestMap = make(map[string]time.Time)
	requestInterval     = 5 * time.Minute
	emailTemplate       *template.Template
)

func (api *recordAuthApi) requestEmailAuthToken(c echo.Context) error {
	mapsMutex.Lock()
	defer mapsMutex.Unlock()

	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	email := c.FormValue("email")
	expirationTime := time.Now().UTC().Add(requestInterval)

	//-------------------------------------//

	emailMutexMapLock.Lock()
	defer emailMutexMapLock.Unlock()

	emailMutex, exists := emailMutexMap[email]
	if !exists {
		emailMutex = &sync.Mutex{}
		emailMutexMap[email] = emailMutex
	}
	emailMutex.Lock()

	// Check if another request was made within the last 5 minutes
	lastRequestTime, exists := emailLastRequestMap[email]
	if exists && expirationTime.Sub(lastRequestTime) < requestInterval {
		// Another request was made within the last 5 minutes
		emailMutex.Unlock()
		return NewBadRequestError("Only one request allowed every 5 minutes", nil)
	}

	// Update last request time for the email
	emailLastRequestMap[email] = expirationTime

	// Unlock the email-specific mutex
	emailMutex.Unlock()

	//-------------------------------------//

	token := security.RandomString(24)

	AuthRecord, err := api.app.Dao().FindAuthRecordByEmail(collection.Name, email)
	if AuthRecord == nil || err != nil {
		return NewBadRequestError("No user found with that email!", nil)
	}

	if !AuthRecord.GetBool("emailAuthJwtEnabled") {
		return NewUnauthorizedError("Sign in method not supported", nil)
	}

	claims := jwt.MapClaims{
		"token":      token,
		"email":      email,
		"collection": collection.Id,
	}

	jwtToken, err := security.NewJWT(claims, AuthRecord.TokenKey(), 300)
	if err != nil {
		return NewBadRequestError("Problem creating a sign in code", nil)
	}

	AuthRecord.Set("emailAuthJwt", jwtToken)

	if err := api.app.Dao().SaveRecord(AuthRecord); err != nil {
		return NewBadRequestError("Unable to create token", nil)
	}

	data := struct {
		Token    string
		LinkUrl  string
		HomePage string
	}{
		Token:    token,
		LinkUrl:  c.FormValue("link") + "/api/auth/sso/link?ssoToken=" + token + "&ssoEmail=" + email,
		HomePage: c.FormValue("link"),
	}
	// Create a buffer to store the filled-in template
	var modifiedHTMLBuffer bytes.Buffer

	// Apply the dynamic data to the template and write the result to the buffer
	err = emailTemplate.Execute(&modifiedHTMLBuffer, data)
	if err != nil {
		panic(err)
	}

	// Get the final HTML string with dynamic content
	modifiedHTML := modifiedHTMLBuffer.String()

	message := &mailer.Message{
		From: mail.Address{
			Address: api.app.Settings().Meta.SenderAddress,
			Name:    api.app.Settings().Meta.SenderName,
		},
		To:      []mail.Address{{Address: email}},
		Subject: "Email Auth Token",
		HTML:    modifiedHTML,
		// bcc, cc, attachments and custom headers are also supported...
	}

	return api.app.NewMailClient().Send(message)
}

func (api *recordAuthApi) authWithEmailJWT(c echo.Context) error {

	if c.FormValue("create") == "true" {
		return api.signUpWithEmailJWT(c)
	}

	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	email := c.FormValue("email")
	token := c.FormValue("token")

	AuthRecord, err := api.app.Dao().FindAuthRecordByEmail(collection.Name, email)
	if AuthRecord == nil || err != nil {
		return NewBadRequestError("No user found with that email!", nil)
	}

	if !AuthRecord.GetBool("emailAuthJwtEnabled") {
		return NewUnauthorizedError("Sign in method not supported", nil)
	}

	authRecordStoredJWT := AuthRecord.GetString("emailAuthJwt")

	if authRecordStoredJWT == "" || email == "" || token == "" {
		return NewForbiddenError("Invalid code", nil)
	}

	storedJwtToken, err := security.ParseJWT(authRecordStoredJWT, AuthRecord.TokenKey())
	if err != nil {
		return NewBadRequestError("Problem validating a sign in code", nil)
	}

	if err := storedJwtToken.Valid(); err != nil {
		AuthRecord.Set("emailAuthJwt", "")
		if err := api.app.Dao().SaveRecord(AuthRecord); err != nil {
			return NewBadRequestError("Unable to create token", nil)
		}
		return NewForbiddenError("Code expired", nil)
	}

	if token != storedJwtToken["token"] || AuthRecord.Email() != storedJwtToken["email"] || AuthRecord.Collection().Id != storedJwtToken["collection"] {
		NewForbiddenError("Problem validating a sign in code", nil)
	}

	AuthRecord.Set("emailAuthJwt", "")

	if err := api.app.Dao().SaveRecord(AuthRecord); err != nil {
		return NewBadRequestError("Unable to create token", nil)
	}

	return RecordAuthResponse(api.app, c, AuthRecord, nil)
}

func (api *recordAuthApi) signUpWithEmailJWT(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	email := c.FormValue("email")
	username := c.FormValue("username")

	AuthRecord, _ := api.app.Dao().FindAuthRecordByEmail(collection.Name, email)
	if AuthRecord != nil {
		return NewBadRequestError("An account with that email already exists", nil)
	}

	record := models.NewRecord(collection)

	record.Set("email", email)
	record.Set("username", username)
	record.Set("emailAuthJwtEnabled", "true")
	//Sets a password so its not null
	randomStringPWD := security.RandomString(30)
	record.Set("password", randomStringPWD)
	record.Set("passwordConfirm", randomStringPWD)

	if err := api.app.Dao().SaveRecord(record); err != nil {
		return NewBadRequestError("Unable to create token", nil)
	}

	return RecordAuthResponse(api.app, c, record, nil)
}

func (api *recordAuthApi) toggleEmailAuthJWT(c echo.Context) error {
	authRecord, _ := c.Get(ContextAuthRecordKey).(*models.Record)
	if authRecord == nil {
		return NewForbiddenError("Missing required data", nil)
	}

	if authRecord.GetBool("emailAuthJwtEnabled") {
		/**
		Runs if the user has Email Auth enabled

		Because they do, it gets the password provided in the submited data and sets it as there account password
		Then toggles the flags to reflect the changes only if the passwords match
		*/
		newPassword := strings.ReplaceAll(c.FormValue("passwordA"), " ", "")
		password := PasswordN{Value: newPassword}
		if err := password.ValidateNPassword(); err != nil {
			return NewBadRequestError("Password does not meet the required format. 1 letter, 1 number, 1 symbol, minimum 8 characters", nil)
		}
		authRecord.Set("emailAuthJwtEnabled", "false")
		authRecord.SetPassword(newPassword)
		if authRecord.ValidatePassword(newPassword) {
			if err := api.app.Dao().SaveRecord(authRecord); err != nil {
				return NewApiError(500, "Unable to set new password", nil)
			}
		} else {
			return NewApiError(500, "Problem validating new password", nil)
		}
	} else {
		/**
		Runs if the user doesn't have Email Auth on but is enabling it

		It removes there password and generates a new key for there jwt token to use
		Then updates the flags to reflect the changes
		*/
		authRecord.Set("emailAuthJwtEnabled", "true")
		api.app.Dao().DB()
		authRecord.Set("passwordHash", "")
		authRecord.Set("tokenKey", security.RandomString(24))
		if err := api.app.Dao().SaveRecord(authRecord); err != nil {
			return NewApiError(500, "Unable to remove password", nil)
		}

	}

	return nil
}

//-----------

func (api *recordAuthApi) requestPasswordReset(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	authOptions := collection.AuthOptions()
	if !authOptions.AllowUsernameAuth && !authOptions.AllowEmailAuth {
		return NewBadRequestError("The collection is not configured to allow password authentication.", nil)
	}

	form := forms.NewRecordPasswordResetRequest(api.app, collection)
	if err := c.Bind(form); err != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", err)
	}

	if err := form.Validate(); err != nil {
		return NewBadRequestError("An error occurred while validating the form.", err)
	}

	event := new(core.RecordRequestPasswordResetEvent)
	event.HttpContext = c
	event.Collection = collection

	submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeRequestPasswordResetRequest().Trigger(event, func(e *core.RecordRequestPasswordResetEvent) error {
				// run in background because we don't need to show the result to the client
				routine.FireAndForget(func() {
					if err := next(e.Record); err != nil {
						api.app.Logger().Debug(
							"Failed to send password reset email",
							slog.String("error", err.Error()),
						)
					}
				})

				return api.app.OnRecordAfterRequestPasswordResetRequest().Trigger(event, func(e *core.RecordRequestPasswordResetEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})

	// eagerly write 204 response and skip submit errors
	// as a measure against emails enumeration
	if !c.Response().Committed {
		c.NoContent(http.StatusNoContent)
	}

	return submitErr
}

func (api *recordAuthApi) confirmPasswordReset(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	form := forms.NewRecordPasswordResetConfirm(api.app, collection)
	if readErr := c.Bind(form); readErr != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", readErr)
	}

	event := new(core.RecordConfirmPasswordResetEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmPasswordResetRequest().Trigger(event, func(e *core.RecordConfirmPasswordResetEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to set new password.", err)
				}

				return api.app.OnRecordAfterConfirmPasswordResetRequest().Trigger(event, func(e *core.RecordConfirmPasswordResetEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})

	return submitErr
}

func (api *recordAuthApi) requestVerification(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	form := forms.NewRecordVerificationRequest(api.app, collection)
	if err := c.Bind(form); err != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", err)
	}

	if err := form.Validate(); err != nil {
		return NewBadRequestError("An error occurred while validating the form.", err)
	}

	event := new(core.RecordRequestVerificationEvent)
	event.HttpContext = c
	event.Collection = collection

	submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeRequestVerificationRequest().Trigger(event, func(e *core.RecordRequestVerificationEvent) error {
				// run in background because we don't need to show the result to the client
				routine.FireAndForget(func() {
					if err := next(e.Record); err != nil {
						api.app.Logger().Debug(
							"Failed to send verification email",
							slog.String("error", err.Error()),
						)
					}
				})

				return api.app.OnRecordAfterRequestVerificationRequest().Trigger(event, func(e *core.RecordRequestVerificationEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})

	// eagerly write 204 response and skip submit errors
	// as a measure against users enumeration
	if !c.Response().Committed {
		c.NoContent(http.StatusNoContent)
	}

	return submitErr
}

func (api *recordAuthApi) confirmVerification(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	form := forms.NewRecordVerificationConfirm(api.app, collection)
	if readErr := c.Bind(form); readErr != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", readErr)
	}

	event := new(core.RecordConfirmVerificationEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmVerificationRequest().Trigger(event, func(e *core.RecordConfirmVerificationEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("An error occurred while submitting the form.", err)
				}

				return api.app.OnRecordAfterConfirmVerificationRequest().Trigger(event, func(e *core.RecordConfirmVerificationEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})

	return submitErr
}

func (api *recordAuthApi) requestEmailChange(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	record, _ := c.Get(ContextAuthRecordKey).(*models.Record)
	if record == nil {
		return NewUnauthorizedError("The request requires valid auth record.", nil)
	}

	form := forms.NewRecordEmailChangeRequest(api.app, record)
	if err := c.Bind(form); err != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", err)
	}

	event := new(core.RecordRequestEmailChangeEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record

	return form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			return api.app.OnRecordBeforeRequestEmailChangeRequest().Trigger(event, func(e *core.RecordRequestEmailChangeEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to request email change.", err)
				}

				return api.app.OnRecordAfterRequestEmailChangeRequest().Trigger(event, func(e *core.RecordRequestEmailChangeEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})
}

func (api *recordAuthApi) confirmEmailChange(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	form := forms.NewRecordEmailChangeConfirm(api.app, collection)
	if readErr := c.Bind(form); readErr != nil {
		return NewBadRequestError("An error occurred while loading the submitted data.", readErr)
	}

	event := new(core.RecordConfirmEmailChangeEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmEmailChangeRequest().Trigger(event, func(e *core.RecordConfirmEmailChangeEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to confirm email change.", err)
				}

				return api.app.OnRecordAfterConfirmEmailChangeRequest().Trigger(event, func(e *core.RecordConfirmEmailChangeEvent) error {
					if e.HttpContext.Response().Committed {
						return nil
					}

					return e.HttpContext.NoContent(http.StatusNoContent)
				})
			})
		}
	})

	return submitErr
}

func (api *recordAuthApi) listExternalAuths(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	id := c.PathParam("id")
	if id == "" {
		return NewNotFoundError("", nil)
	}

	record, err := api.app.Dao().FindRecordById(collection.Id, id)
	if err != nil || record == nil {
		return NewNotFoundError("", err)
	}

	externalAuths, err := api.app.Dao().FindAllExternalAuthsByRecord(record)
	if err != nil {
		return NewBadRequestError("Failed to fetch the external auths for the specified auth record.", err)
	}

	event := new(core.RecordListExternalAuthsEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.ExternalAuths = externalAuths

	return api.app.OnRecordListExternalAuthsRequest().Trigger(event, func(e *core.RecordListExternalAuthsEvent) error {
		return e.HttpContext.JSON(http.StatusOK, e.ExternalAuths)
	})
}

func (api *recordAuthApi) unlinkExternalAuth(c echo.Context) error {
	collection, _ := c.Get(ContextCollectionKey).(*models.Collection)
	if collection == nil {
		return NewNotFoundError("Missing collection context.", nil)
	}

	id := c.PathParam("id")
	provider := c.PathParam("provider")
	if id == "" || provider == "" {
		return NewNotFoundError("", nil)
	}

	record, err := api.app.Dao().FindRecordById(collection.Id, id)
	if err != nil || record == nil {
		return NewNotFoundError("", err)
	}

	/**
	This checks to see that the user can login after they remove OAuth, they either have emailAuth or if they don't then they also don't have a password by default so they need to create a new one.
	*/
	if !record.GetBool("emailAuthJwtEnabled") {
		newPassword := c.FormValue("password")
		if newPassword != "" {
			record.SetPassword(newPassword)
			if !record.ValidatePassword(newPassword) {
				return NewBadRequestError("Problem validating new password", nil)
			} else {
				if err := api.app.Dao().SaveRecord(record); err != nil {
					return err
				}
			}
		} else {
			return NewBadRequestError("You must set a password before unlinking OAuth provider", nil)
		}
	}

	externalAuth, err := api.app.Dao().FindExternalAuthByRecordAndProvider(record, provider)
	if err != nil {
		return NewNotFoundError("Missing external auth provider relation.", err)
	}

	event := new(core.RecordUnlinkExternalAuthEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.ExternalAuth = externalAuth

	return api.app.OnRecordBeforeUnlinkExternalAuthRequest().Trigger(event, func(e *core.RecordUnlinkExternalAuthEvent) error {
		if err := api.app.Dao().DeleteExternalAuth(externalAuth); err != nil {
			return NewBadRequestError("Cannot unlink the external auth provider.", err)
		}

		return api.app.OnRecordAfterUnlinkExternalAuthRequest().Trigger(event, func(e *core.RecordUnlinkExternalAuthEvent) error {
			if e.HttpContext.Response().Committed {
				return nil
			}

			return e.HttpContext.NoContent(http.StatusNoContent)
		})
	})
}

// -------------------------------------------------------------------

const oauth2SubscriptionTopic = "@oauth2"

func (api *recordAuthApi) oauth2SubscriptionRedirect(c echo.Context) error {
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if code == "" || state == "" {
		return NewBadRequestError("Invalid OAuth2 redirect parameters.", nil)
	}

	client, err := api.app.SubscriptionsBroker().ClientById(state)
	if err != nil || client.IsDiscarded() || !client.HasSubscription(oauth2SubscriptionTopic) {
		return NewNotFoundError("Missing or invalid OAuth2 subscription client.", err)
	}

	data := map[string]string{
		"state": state,
		"code":  code,
	}

	encodedData, err := json.Marshal(data)
	if err != nil {
		return NewBadRequestError("Failed to marshalize OAuth2 redirect data.", err)
	}

	msg := subscriptions.Message{
		Name: oauth2SubscriptionTopic,
		Data: encodedData,
	}

	client.Send(msg)

	return c.Redirect(http.StatusTemporaryRedirect, "../_/#/auth/oauth2-redirect")
}

//--------------------------------------------------------------------

type PasswordN struct {
	Value string
}

func (p PasswordN) ValidateNPassword() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Value, validation.Required, validation.Length(8, 0)),
		validation.Field(&p.Value, validation.By(validatePassword)),
	)
}

func validatePassword(value interface{}) error {
	password, ok := value.(string)
	if !ok {
		return validation.NewError("", "invalid type for password")
	}

	// Check if the password contains at least one letter, one digit, and one special character.

	var (
		hasLetter, hasDigit, hasSpecialChar bool
	)

	for _, char := range password {
		switch {
		case unicode.IsLetter(char):
			hasLetter = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecialChar = true
		}
	}

	if !(hasLetter && hasDigit && hasSpecialChar) {
		return validation.NewError("", "password must contain at least 1 letter, 1 digit, and 1 special character")
	}

	return nil
}
