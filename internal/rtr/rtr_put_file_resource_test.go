package rtr_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const putFileResourceName = "crowdstrike_rtr_put_file.test"

type putFileConfig struct {
	Name        string
	Description string
	FilePath    string
	Comment     string
}

func (config *putFileConfig) String() string {
	return fmt.Sprintf(`
resource "crowdstrike_rtr_put_file" "test" {
  name        = %q
  description = %q
  file_path   = %q
  comment     = %q
}
`, config.Name, config.Description, config.FilePath, config.Comment)
}

func (config *putFileConfig) TestChecks() resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(putFileResourceName, "id"),
		resource.TestCheckResourceAttrSet(putFileResourceName, "last_updated"),
		resource.TestCheckResourceAttrSet(putFileResourceName, "sha256"),
		resource.TestCheckResourceAttrSet(putFileResourceName, "size"),
		resource.TestCheckResourceAttr(putFileResourceName, "name", config.Name),
		resource.TestCheckResourceAttr(putFileResourceName, "description", config.Description),
		resource.TestCheckResourceAttr(putFileResourceName, "comment", config.Comment),
	)
}

func createTempPutFile(t *testing.T, fileName string) string {
	t.Helper()

	tempFilePath := filepath.Join(t.TempDir(), fileName)
	writeTempPutFileContent(t, tempFilePath, "terraform acceptance testing rtr put file!")

	return tempFilePath
}

func writeTempPutFileContent(
	t *testing.T,
	filePath string,
	content string,
) {
	t.Helper()

	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file %q: %v", filePath, err)
	}
}

func TestAccRTRPutFileResource(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	tempFilePath := createTempPutFile(t, "rtr-put-file.txt")

	testCases := []struct {
		name   string
		config putFileConfig
	}{
		{
			name: "put_file_initial",
			config: putFileConfig{
				Name:        rName,
				Description: "RTR put file acceptance test (initial)",
				FilePath:    tempFilePath,
				Comment:     "created by terraform acceptance test",
			},
		},
		{
			name: "put_file_updated",
			config: putFileConfig{
				Name:        rName + "-updated",
				Description: "RTR put file acceptance test (updated)",
				FilePath:    tempFilePath,
				Comment:     "updated by terraform acceptance test",
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: acctest.ProviderConfig + tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      putFileResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
					"file_path",
				},
			})

			return steps
		}(),
	})
}

func TestAccRTRPutFileResource_FileHashChangeRequiresReplace(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	tempFilePath := createTempPutFile(t, "rtr-put-file-replace.txt")

	config := putFileConfig{
		Name:        rName,
		Description: "RTR put file acceptance test (replace on hash change)",
		FilePath:    tempFilePath,
		Comment:     "replace check",
	}

	idChanges := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + config.String(),
				Check:  config.TestChecks(),
				ConfigStateChecks: []statecheck.StateCheck{
					idChanges.AddStateValue(putFileResourceName, tfjsonpath.New("id")),
				},
			},
			{
				PreConfig: func() {
					writeTempPutFileContent(t, tempFilePath, "terraform acceptance testing rtr put file! content changed")
				},
				Config: acctest.ProviderConfig + config.String(),
				Check:  config.TestChecks(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(putFileResourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idChanges.AddStateValue(putFileResourceName, tfjsonpath.New("id")),
				},
			},
			{
				ResourceName:      putFileResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
					"file_path",
				},
			},
		},
	})
}
