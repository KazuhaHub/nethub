package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guiacme"
)

var ErrGUIAccount = errors.New("private GUI account operation unavailable")

type GUIAccountOptions struct {
	Directory, ConfigFile, Action, BackupDirectory, TermsFile string
	AllowCreate                                               bool
}

type GUIAccountResult struct {
	State          string  `json:"state"`
	TermsReference *string `json:"terms_reference,omitempty"`
}

func validGUIAccountOptions(o GUIAccountOptions) bool {
	if o.Directory == "" || o.ConfigFile == "" {
		return false
	}
	switch o.Action {
	case "initialize", "terms", "lookup":
		return o.BackupDirectory == "" && !o.AllowCreate && o.TermsFile == ""
	case "backup", "verify-backup", "restore":
		return o.BackupDirectory != "" && !o.AllowCreate && o.TermsFile == ""
	case "register":
		return o.BackupDirectory != "" && o.AllowCreate && o.TermsFile != ""
	default:
		return false
	}
}

func decodeGUIAccountConsent(data []byte) (string, error) {
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 1 {
		return "", ErrGUIAccount
	}
	value, ok := fields["accepted_terms_reference"]
	var terms string
	if !ok || len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &terms) != nil || len(terms) > 2048 {
		return "", ErrGUIAccount
	}
	return terms, nil
}

type guiAccountOperations interface {
	Initialize(context.Context) error
	Backup(context.Context, string) error
	VerifyBackup(context.Context, string) error
	Restore(context.Context, string) error
	CurrentTerms(context.Context) (string, error)
	EnsureAccount(context.Context, bool, string) (guiacme.Account, error)
}

func runGUIAccountAction(ctx context.Context, s guiAccountOperations, o GUIAccountOptions, terms string) (GUIAccountResult, error) {
	if !validGUIAccountOptions(o) || ctx.Err() != nil {
		return GUIAccountResult{}, ErrGUIAccount
	}
	var err error
	state := ""
	switch o.Action {
	case "initialize":
		err = s.Initialize(ctx)
		state = "initialized"
	case "backup":
		err = s.Backup(ctx, o.BackupDirectory)
		state = "backed_up"
	case "verify-backup":
		err = s.VerifyBackup(ctx, o.BackupDirectory)
		state = "backup_verified"
	case "restore":
		err = s.Restore(ctx, o.BackupDirectory)
		state = "restored"
	case "terms":
		value, err := s.CurrentTerms(ctx)
		if err != nil {
			return GUIAccountResult{}, err
		}
		return GUIAccountResult{State: "review_terms", TermsReference: &value}, nil
	case "lookup":
		_, err = s.EnsureAccount(ctx, false, "")
		state = "registered"
	case "register":
		if err = s.VerifyBackup(ctx, o.BackupDirectory); err == nil {
			_, err = s.EnsureAccount(ctx, true, terms)
		}
		state = "registered"
	}
	if err != nil {
		return GUIAccountResult{}, err
	}
	return GUIAccountResult{State: state}, nil
}
