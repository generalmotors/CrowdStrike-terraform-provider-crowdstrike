package rtr

import "github.com/hashicorp/terraform-plugin-framework/diag"

const (
	putFileNotFound  = "RTR Put File not found"
	notFoundRemoving = "%s, removing from state"
	rtrPutFile       = "RTR Put File"
)

func newRtrPutFileNotFoundError(details string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(putFileNotFound, details)
}
