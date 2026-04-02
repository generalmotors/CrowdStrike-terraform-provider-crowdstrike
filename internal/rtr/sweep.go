package rtr

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_rtr_put_files", sweepRtrPutFiles)
}

func sweepRtrPutFiles(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	params := real_time_response_admin.NewRTRGetPutFilesV2ParamsWithContext(ctx)
	params.WithContext(ctx)

	resp, err := client.RealTimeResponseAdmin.RTRGetPutFilesV2(params)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping RTR Put File sweep: %q", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing RTR Put Files: %w", err)
	}

	if resp.Payload == nil || resp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, file := range resp.Payload.Resources {

		name := file.Name
		if len(name) == 0 {
			continue
		}

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping RTR Put File %q (not a test resource)", name)
			continue
		}

		id := file.ID
		if len(id) == 0 {
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			id,
			name,
			deleteRtrPutFile,
		))

	}

	return sweepables, nil
}

func deleteRtrPutFile(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	params := real_time_response_admin.NewRTRDeletePutFilesParamsWithContext(ctx)
	params.SetIds(id)

	_, err := client.RealTimeResponseAdmin.RTRDeletePutFiles(params)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for RTR Put File %q: %q", id, err)
			return nil
		}
		return err
	}

	return nil
}
