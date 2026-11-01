package resourcecatalog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

func physicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrUnavailable
	}
	suffix := []string{}
	for {
		resolved, errResolve := filepath.EvalSymlinks(abs)
		if errResolve == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(errResolve) {
			return "", ErrUnavailable
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", ErrUnavailable
		}
		suffix = append(suffix, filepath.Base(abs))
		abs = parent
	}
}
func containsPath(parent, child string) bool {
	if runtime.GOOS == "windows" {
		parent = strings.ToLower(parent)
		child = strings.ToLower(child)
	}
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func statePath(configPath, stateDir string) string {
	if stateDir == "" {
		return filepath.Join(filepath.Dir(configPath), ".resource-catalog")
	}
	if !filepath.IsAbs(stateDir) {
		return filepath.Join(filepath.Dir(configPath), stateDir)
	}
	return filepath.Clean(stateDir)
}
func verifySourceMode(configPath, authDir, stateDir string) error {
	f, err := readSource(configPath, false)
	if err != nil {
		return err
	}
	settings := field(f.root, "resource-catalog")
	if scalar(settings, "enabled") != "true" {
		return ErrUnavailable
	}
	expectedState, err := physicalPath(statePath(configPath, scalar(settings, "state-dir")))
	if err != nil || expectedState != stateDir {
		return ErrUnavailable
	}
	configuredAuth := scalar(f.root, "auth-dir")
	if oauth := field(f.root, "oauth"); field(oauth, "auth-dir") != nil {
		configuredAuth = scalar(oauth, "auth-dir")
	}
	if configuredAuth == "" {
		return ErrUnavailable
	}
	resolved, err := util.ResolveAuthDir(configuredAuth)
	if err != nil {
		return ErrUnavailable
	}
	expectedAuth, err := physicalPath(resolved)
	if err != nil || expectedAuth != authDir {
		return ErrUnavailable
	}
	return nil
}
