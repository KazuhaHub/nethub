package relaytoken

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"time"
)

var commandProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Command retains private host input before preparation or active effects.
// It contains no token/key bytes and does not establish filesystem authority.
type Command struct {
	Version          int       `json:"version"`
	Directory        string    `json:"deployment"`
	Project          string    `json:"project"`
	ComposeFile      string    `json:"compose_file"`
	SuccessorBackup  string    `json:"successor_backup"`
	Request          Request   `json:"request"`
	OriginalBaseline string    `json:"original_baseline_sha256"`
	CreatedAt        time.Time `json:"created_at"`
}

func (c Command) Valid() bool {
	path := func(value string) bool {
		return len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value
	}
	raw, err := json.Marshal(c)
	return err == nil && len(raw) <= 16383 && c.Version == 1 && c.Request.Valid() && digest.MatchString(c.OriginalBaseline) &&
		commandProject.MatchString(c.Project) && path(c.Directory) && path(c.SuccessorBackup) &&
		(c.ComposeFile == "" || path(c.ComposeFile)) && !c.CreatedAt.IsZero()
}
