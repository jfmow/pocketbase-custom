package models_test

import (
	"testing"

	"github.com/jfmow/pocketbase-custom/models"
)

func TestExternalAuthTableName(t *testing.T) {
	t.Parallel()

	m := models.ExternalAuth{}
	if m.TableName() != "_externalAuths" {
		t.Fatalf("Unexpected table name, got %q", m.TableName())
	}
}
