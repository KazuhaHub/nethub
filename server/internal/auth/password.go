package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const MaxPasswordBytes = 1024

// HashPassword uses the deployment's initial Argon2id work factor. Parameters
// and a random 16-byte salt are encoded in the PHC string for future upgrades.
func HashPassword(password string) (string, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return "", errors.New("password length is outside the supported range")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("password salt generation failed")
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword bounds stored parameters before allocating memory. A corrupt
// or unsupported PHC string is an error, never a reason to bypass verification.
func VerifyPassword(encoded, password string) (bool, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes || len(encoded) > 256 || strings.ContainsAny(encoded, "\r\n") {
		return false, errors.New("invalid password input")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("invalid password hash")
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return false, errors.New("invalid password parameters")
	}
	values := [3]uint32{}
	for i, key := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(parameters[i], key) {
			return false, errors.New("invalid password parameters")
		}
		value := strings.TrimPrefix(parameters[i], key)
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != value {
			return false, errors.New("invalid password parameters")
		}
		values[i] = uint32(n)
	}
	memory, iterations, parallelism := values[0], values[1], values[2]
	if memory < 19*1024 || memory > 64*1024 || iterations < 2 || iterations > 4 || parallelism != 1 {
		return false, errors.New("unsupported password work factor")
	}
	decode := base64.RawStdEncoding.Strict().DecodeString
	salt, err := decode(parts[4])
	if err != nil || len(salt) != 16 {
		return false, errors.New("invalid password salt")
	}
	want, err := decode(parts[5])
	if err != nil || len(want) != 32 {
		return false, errors.New("invalid password digest")
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}
