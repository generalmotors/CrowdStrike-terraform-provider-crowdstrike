package rtr

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &rtrPutFileResource{}
	_ resource.ResourceWithConfigure   = &rtrPutFileResource{}
	_ resource.ResourceWithImportState = &rtrPutFileResource{}
	_ resource.ResourceWithModifyPlan  = &rtrPutFileResource{}
)

var (
	documentationSection        string         = "Real Time Response"
	resourceMarkdownDescription string         = "This resource allows management of Real Time Response (RTR) Put Files in the CrowdStrike Falcon platform. RTR Put Files can be put and executed on hosts through the RTR console."
	requiredScopes              []scopes.Scope = rtrScopes
)

func NewRtrPutFileResource() resource.Resource {
	return &rtrPutFileResource{}
}

type rtrPutFileResource struct {
	client *client.CrowdStrikeAPISpecification
}

type rtrPutFileResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Comment     types.String `tfsdk:"comment"`
	Description types.String `tfsdk:"description"`
	FilePath    types.String `tfsdk:"file_path"`
	LastUpdated types.String `tfsdk:"last_updated"`
	Name        types.String `tfsdk:"name"`
	Sha256      types.String `tfsdk:"sha256"`
	Size        types.Int64  `tfsdk:"size"`
}

func (f *rtrPutFileResourceModel) wrap(
	file models.EmpowerapiRemoteCommandPutFileV2,
) diag.Diagnostics { //nolint:unparam
	var diags diag.Diagnostics

	f.ID = types.StringValue(file.ID)
	f.Comment = types.StringValue(file.CommentsForAuditLog)
	f.Description = types.StringValue(file.Description)
	f.Name = types.StringValue(file.Name)
	f.Sha256 = types.StringValue(file.Sha256)
	f.Size = types.Int64PointerValue(file.Size)

	return diags
}

func (r *rtrPutFileResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *rtrPutFileResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_rtr_put_file"
}

func (r *rtrPutFileResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the Rtr.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name to upload the file as.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the file.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"file_path": schema.StringAttribute{
				Required:    true,
				WriteOnly:   true, // don't store in state
				Description: "Local path to the file.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Audit comment to add to the file on upload.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"sha256": schema.StringAttribute{
				Computed:    true,
				Description: "The Sha256 hash of the content at file_path.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(
							`^[a-f0-9]{64}$`),
						"must be a valid SHA256 hash",
					),
				},
			},
			"size": schema.Int64Attribute{
				Computed:    true,
				Description: "Size of the uploaded file.",
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *rtrPutFileResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan rtrPutFileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config rtrPutFileResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(config.FilePath.ValueString()) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("file_path"),
			"file_path must be set",
			"file_path in plan has length of 0",
		)
		return
	}

	planHash, err := computeSha256Hash(config.FilePath.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("sha256"),
			"Unable to compute hash",
			"SHA256 of file could be not be computed",
		)
		return
	}

	plan.Sha256 = types.StringValue(planHash)
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if req.State.Raw.IsNull() {
		return
	}

	var state rtrPutFileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// replace resource if plan sha256 is different than state
	if planHash != state.Sha256.ValueString() {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("sha256"))
	}
}

func (r *rtrPutFileResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan rtrPutFileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var config rtrPutFileResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	file, err := os.Open(config.FilePath.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("file_path"),
			"Unable to open file",
			fmt.Sprintf("Failed to open %q: %s", config.FilePath.ValueString(), err),
		)
		return
	}
	defer file.Close()

	// Ensure hash of the file being uploaded equals hash of the file from plan
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("sha256"),
			"Unable to compute hash",
			"SHA256 of file could be not be computed",
		)
		return
	}
	createHash := fmt.Sprintf("%x", hash.Sum(nil))

	if createHash != plan.Sha256.ValueString() {
		resp.Diagnostics.AddAttributeError(
			path.Root("sha256"),
			"Hash of file has changed",
			"SHA256 hash of file between plan and apply does not match",
		)
		return
	}

	// reset bytes of file upload
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("file_path"),
			"Unable to reset file stream",
			fmt.Sprintf("Failed to reset file %q for upload: %s", config.FilePath.ValueString(), err),
		)
		return
	}

	params := real_time_response_admin.NewRTRCreatePutFilesV2ParamsWithContext(ctx)
	params.Name = plan.Name.ValueStringPointer()
	params.Description = plan.Description.ValueString()
	params.File = file
	params.CommentsForAuditLog = plan.Comment.ValueStringPointer()

	apiResponse, err := r.client.RealTimeResponseAdmin.RTRCreatePutFilesV2(params)
	if err != nil {
		resp.Diagnostics.AddError("Error creating put file", err.Error())
		return
	}

	if apiResponse == nil || apiResponse.Payload == nil || len(apiResponse.Payload.Resources) == 0 || apiResponse.Payload.Resources[0] == nil {
		resp.Diagnostics.AddError("Error creating RTR Put File", "API returned unexpected create response")
		return
	}

	plan.ID = types.StringValue(apiResponse.Payload.Resources[0].ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(plan.wrap(*apiResponse.Payload.Resources[0])...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rtrPutFileResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state rtrPutFileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fileID := state.ID.ValueString()
	file, diags := getRtrPutFile(ctx, r.client, fileID)
	if diags.HasError() {
		for _, d := range diags.Errors() {
			if d.Summary() == putFileNotFound {
				tflog.Warn(
					ctx,
					fmt.Sprintf(notFoundRemoving, fmt.Sprintf("%s %s", rtrPutFile, fileID)),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(file)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *rtrPutFileResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.AddError("Update not supported", "RTR Put Files require replacement, this resource does not support in-place updates.")
}

func (r *rtrPutFileResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state rtrPutFileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := real_time_response_admin.NewRTRDeletePutFilesParamsWithContext(ctx)
	params.SetIds(state.ID.ValueString())

	ok, err := r.client.RealTimeResponseAdmin.RTRDeletePutFiles(params)
	if err != nil {
		errMsg := err.Error()

		if strings.Contains(strings.ToLower(errMsg), "not found") || strings.Contains(errMsg, "404") {
			return
		}

		resp.Diagnostics.AddError(
			"Error deleting RTR Put File",
			fmt.Sprintf(
				"Could not delete RTR Put File %q, error: %s",
				state.ID.ValueString(),
				err.Error(),
			),
		)
		return
	}

	if ok != nil {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Successfully deleted RTR Put File %q",
				state.ID.ValueString(),
			),
		)
	}
}

func (r *rtrPutFileResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func computeSha256Hash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	return hashString, nil
}

func getRtrPutFile(ctx context.Context, client *client.CrowdStrikeAPISpecification, fileID string) (models.EmpowerapiRemoteCommandPutFileV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := real_time_response_admin.NewRTRGetPutFilesV2ParamsWithContext(ctx)
	params.SetIds([]string{fileID})

	resp, err := client.RealTimeResponseAdmin.RTRGetPutFilesV2(params)
	if resp != nil &&
		resp.Payload != nil &&
		len(resp.Payload.Resources) > 0 &&
		resp.Payload.Resources[0] != nil {
		return *resp.Payload.Resources[0], diags
	}

	if err != nil {
		if _, ok := err.(*real_time_response_admin.RTRGetPutFilesV2NotFound); ok {
			diags.Append(
				newRtrPutFileNotFoundError(
					fmt.Sprintf("No RTR Put File found with ID: %q", fileID),
				),
			)
		} else {
			diags.AddError(
				"Error reading RTR Put File",
				fmt.Sprintf("Could not read Put File ID: %q", fileID),
			)
		}
	} else {
		diags.Append(
			newRtrPutFileNotFoundError(
				fmt.Sprintf("RTR Put File with ID %q not found in API response", fileID),
			),
		)
	}

	return models.EmpowerapiRemoteCommandPutFileV2{}, diags
}
