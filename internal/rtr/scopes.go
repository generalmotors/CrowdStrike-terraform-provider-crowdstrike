package rtr

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var rtrScopes = []scopes.Scope{
	{
		Name:  "Real Time Response (Admin)",
		Read:  true,
		Write: true,
	},
}
