package guiacme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrState = errors.New("ACME account state needs local review")
var ErrBusy = errors.New("ACME account operation already running")

const accountStateLimit = 32768

// AccountStore is private issuer state. It has no ordinary JSON representation
// and never exports the account signing key to its caller or an application API.
type AccountStore struct {
	directory string
	config    Config
	binding   string
	origins   map[string]bool
}

type accountState struct {
	Version   int    `json:"version"`
	Policy    string `json:"policy"`
	Key       string `json:"private_pkcs8"`
	URI       string `json:"account_uri,omitempty"`
	OrdersURL string `json:"orders_url,omitempty"`
}

// NewAccountStore performs no initialization, network request or key generation.
// Config.Key must be nil; only the store's durable key may sign account requests.
func NewAccountStore(directory string, config Config) (*AccountStore, error) {
	if config.Key != nil || len(directory) > 4096 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return nil, ErrConfig
	}
	origins, contacts, err := validatePolicy(config)
	if err != nil {
		return nil, err
	}
	var sorted []string
	for origin := range origins {
		sorted = append(sorted, origin)
	}
	sort.Strings(sorted)
	policy, _ := json.Marshal(struct {
		Directory         string
		Origins, Contacts []string
	}{config.DirectoryURL, sorted, contacts})
	digest := sha256.Sum256(policy)
	config.AdditionalOrigins = append([]string(nil), config.AdditionalOrigins...)
	if config.Roots != nil {
		config.Roots = config.Roots.Clone()
	}
	return &AccountStore{directory: directory, config: config, binding: hex.EncodeToString(digest[:]), origins: origins}, nil
}

// AllowsURL checks the store's immutable operator policy without opening account
// state, creating a key or sending a request. It is suitable for saved job URLs.
func (s *AccountStore) AllowsURL(value string) bool {
	if s == nil {
		return false
	}
	u, ok := endpoint(value)
	return ok && s.origins[u.Scheme+"://"+u.Host]
}

func (s *AccountStore) path(name string) string { return filepath.Join(s.directory, name) }

func (s *AccountStore) checkParent() error {
	parent := filepath.Dir(s.directory)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return ErrState
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || !accountOwned(info) || !accountParentMode(info) {
		return ErrState
	}
	return nil
}

// Initialize is an explicit offline operation. A missing/corrupt state file in a
// previously used namespace is never silently replaced with another account key.
func (s *AccountStore) Initialize(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if s.checkParent() != nil {
		return ErrState
	}
	if err := os.Mkdir(s.directory, 0700); err != nil {
		if !os.IsExist(err) {
			return ErrState
		}
	} else if os.Chmod(s.directory, 0700) != nil || accountSync(filepath.Dir(s.directory)) != nil {
		return ErrState
	}
	if accountProtected(s.directory, true) != nil {
		return ErrState
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return ErrState
	}
	_, stateError := os.Lstat(s.path("account.json"))
	initialize := os.IsNotExist(stateError) && len(entries) == 0
	if stateError != nil && !initialize {
		return ErrState
	}
	lease, err := s.lease(initialize)
	if err != nil {
		return err
	}
	defer accountRelease(lease)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if _, err := os.Lstat(s.path("account.json")); err == nil {
		_, _, err = s.load()
		return err
	} else if !os.IsNotExist(err) {
		return ErrState
	}
	if !initialize {
		return ErrState
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrState
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ErrState
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return s.save(accountState{Version: 1, Policy: s.binding, Key: base64.RawStdEncoding.EncodeToString(der)})
}

// EnsureAccount holds the OS lease across lookup/registration and identity
// persistence. A lost response or interrupted identity write reuses the stored
// key on the next call; ordinary work cannot initialize a missing key namespace.
func (s *AccountStore) EnsureAccount(ctx context.Context, allowCreate bool, acceptedTermsURL string) (Account, error) {
	if ctx.Err() != nil {
		return Account{}, ErrCancelled
	}
	lease, err := s.lease(false)
	if err != nil {
		return Account{}, err
	}
	defer accountRelease(lease)
	state, key, err := s.load()
	if err != nil {
		return Account{}, err
	}
	config := s.config
	config.Key = key
	client, err := New(config)
	if err != nil {
		return Account{}, ErrState
	}
	defer client.Close()
	account, err := client.EnsureAccount(ctx, Registration{AllowCreate: allowCreate, AcceptedTermsURL: acceptedTermsURL, ExpectedURI: state.URI})
	if err != nil {
		return Account{}, err
	}
	if ctx.Err() != nil {
		return Account{}, ErrCancelled
	}
	if state.URI != account.URI || state.OrdersURL != account.OrdersURL {
		state.URI, state.OrdersURL = account.URI, account.OrdersURL
		if s.save(state) != nil {
			return Account{}, ErrState
		}
	}
	return account, nil
}

func (s *AccountStore) load() (accountState, *ecdsa.PrivateKey, error) {
	var state accountState
	data, err := accountRead(s.path("account.json"))
	if err != nil {
		return state, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return accountState{}, nil, ErrState
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return accountState{}, nil, ErrState
	}
	canonical, err := json.MarshalIndent(state, "", "  ")
	if err != nil || !bytes.Equal(data, append(canonical, '\n')) || state.Version != 1 || state.Policy != s.binding || len(state.Key) > 1024 {
		return accountState{}, nil, ErrState
	}
	der, err := base64.RawStdEncoding.Strict().DecodeString(state.Key)
	if err != nil || base64.RawStdEncoding.EncodeToString(der) != state.Key {
		return accountState{}, nil, ErrState
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || !validKey(key) {
		return accountState{}, nil, ErrState
	}
	canonicalDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || !bytes.Equal(der, canonicalDER) {
		return accountState{}, nil, ErrState
	}
	origins, _, _ := validatePolicy(s.config)
	allowed := func(value string) bool { u, ok := endpoint(value); return ok && origins[u.Scheme+"://"+u.Host] }
	if state.URI == "" && state.OrdersURL != "" || state.URI != "" && !allowed(state.URI) || state.OrdersURL != "" && !allowed(state.OrdersURL) {
		return accountState{}, nil, ErrState
	}
	return state, key, nil
}

func (s *AccountStore) save(state accountState) error {
	if state.Policy != s.binding || state.Version != 1 {
		return ErrState
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil || len(data) >= accountStateLimit {
		return ErrState
	}
	return accountWrite(s.path("account.json"), append(data, '\n'))
}
