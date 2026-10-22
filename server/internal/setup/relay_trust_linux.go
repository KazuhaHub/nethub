package setup

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// RunRelayTrust uses the confirmed host authority and exact Compose database
// binding. It starts no service and changes neither signer nor relay material.
func RunRelayTrust(ctx context.Context, o RelayTrustOptions) (RelayTrustResult, error) {
	var result RelayTrustResult
	if ctx.Err() != nil || !validRelayTrustOperation(o) || os.Geteuid() != 0 || !projectName.MatchString(o.Project) {
		return result, ErrRelayTrust
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	directory, err := filepath.Abs(o.Directory)
	if err != nil {
		return result, ErrRelayTrust
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || CheckAuthority(directory) != nil {
		return result, ErrRelayTrust
	}
	lease, err := hostlease.Acquire(filepath.Join(directory, "relay-operation.lock"))
	if err != nil {
		return result, ErrRelayTrust
	}
	defer lease.Close()
	if ctx.Err() != nil || CheckAuthority(directory) != nil {
		return result, ErrRelayTrust
	}
	manifest, err := Load(directory)
	if err != nil || validateIdentity(manifest.Config) != nil {
		return result, ErrRelayTrust
	}
	var candidate *relaytrust.Bundle
	if o.Action == "publish" {
		public, err := rootGUIFile(o.BundleFile, 32768, true)
		if err != nil {
			return result, ErrRelayTrust
		}
		authority, err := rootGUIFile(filepath.Join(directory, "secrets/issuer/ca.pem"), 32768, true)
		if err != nil {
			return result, ErrRelayTrust
		}
		candidate, err = relayTrustCandidate(public, authority, time.Now())
		if err != nil {
			return result, ErrRelayTrust
		}
	}
	host := guiHost{directory: directory, project: o.Project, compose: []string{"compose", "--project-name", o.Project}}
	files := []string{filepath.Join(directory, "docker-compose.yml"), filepath.Join(directory, "docker-compose.override.yml")}
	if o.ComposeFile != "" {
		files = append(files, o.ComposeFile)
	}
	for _, file := range files {
		if _, err := rootGUIFile(file, 262144, false); err != nil {
			return result, ErrRelayTrust
		}
		host.compose = append(host.compose, "--file", file)
	}
	binding, err := host.database(ctx)
	if err != nil {
		return result, ErrRelayTrust
	}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		return result, ErrRelayTrust
	}
	publisher := relaytrust.Publisher{Run: relaytrust.SQLRunner(run), ServerName: manifest.Config.ConsoleHost}
	var generation *relaytrust.Generation
	if o.Action == "current" {
		generation, err = publisher.Current(ctx)
	} else {
		generation, err = publisher.Publish(ctx, o.ExpectedGeneration, candidate.PEM())
	}
	if err != nil {
		return result, ErrRelayTrust
	}
	return relayTrustSummary(generation, manifest.Config.ConsoleHost), nil
}
