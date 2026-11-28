package credentials

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// EnvNameRE is the single source of truth for env var names in identities.yaml
// (token_env and login_recipe placeholders).
var EnvNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

var deniedEnv = map[string]bool{
	"PATH": true, "HOME": true, "GOGC": true, "SOURCE_DATE_EPOCH": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
}

// CheckEnvName rejects malformed names and process/system variables, which are
// not credentials and point to a mistake.
func CheckEnvName(name string) error {
	if !EnvNameRE.MatchString(name) {
		return errors.New("env var name must match ^[A-Z_][A-Z0-9_]*$")
	}
	if deniedEnv[name] || strings.HasPrefix(name, "LD_") {
		return fmt.Errorf("env var %s is a process or system variable, not a credential", name)
	}
	return nil
}

// normalizeEnv applies the value rules. The value never appears in an error.
func normalizeEnv(name, val string) (string, error) {
	if strings.HasSuffix(val, "\r\n") {
		val = val[:len(val)-2]
	} else if strings.HasSuffix(val, "\n") {
		val = val[:len(val)-1]
	}
	if strings.TrimSpace(val) == "" {
		return "", fmt.Errorf("env var %s is empty or unset", name)
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		return "", fmt.Errorf("env var %s contains CR, LF or NUL", name)
	}
	return val, nil
}

// LoadEnv reads a credential from the environment.
func LoadEnv(name string) (Secret, error) { return loadEnv(name, os.Getenv) }

func loadEnv(name string, lookup func(string) string) (Secret, error) {
	if err := CheckEnvName(name); err != nil {
		return Secret{}, err
	}
	v, err := normalizeEnv(name, lookup(name))
	if err != nil {
		return Secret{}, err
	}
	return Secret{b: []byte(v), noFP: true}, nil
}

// LoadEnvFrom is LoadEnv with an explicit lookup (config parse time, tests).
func LoadEnvFrom(name string, lookup func(string) string) (Secret, error) {
	return loadEnv(name, lookup)
}
