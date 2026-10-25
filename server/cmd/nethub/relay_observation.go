package main

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/KazuhaHub/nethub/server/internal/store"
)

func validObservationFlags(origin, userFile, passwordFile string) bool {
	return origin == "" && userFile == "" && passwordFile == "" || origin != "" && userFile != "" && passwordFile != ""
}

func newObserver(origin, userFile, passwordFile string, db *sql.DB, logger *slog.Logger, actionLimit int) (*relaystate.Poller, error) {
	user, userError := readAuthzFile(userFile, 256, true)
	password, passwordError := readAuthzFile(passwordFile, 512, true)
	if userError != nil || passwordError != nil {
		return nil, errors.New("relay observation credential files are invalid")
	}
	return relaystate.New(relaystate.Config{Origin: origin, User: strings.TrimSpace(string(user)),
		Password: strings.TrimSpace(string(password)), Logger: logger, AnomalyActionLimit: actionLimit}, &store.ObservationStore{DB: db})
}
