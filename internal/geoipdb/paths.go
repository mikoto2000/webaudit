package geoipdb

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
)

var windowsAbsolute = regexp.MustCompile(`^(?:[a-zA-Z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/]|$))`)

func ResolveDir(goos string, getenv func(string) string) (string, error) {
	absolute := func(s string) bool {
		if goos == "windows" {
			return windowsAbsolute.MatchString(s)
		}
		return strings.HasPrefix(s, "/")
	}
	join := func(s string) string {
		if goos == "windows" {
			return strings.TrimRight(s, `\/`) + `\webaudit\geoip`
		}
		return path.Join(s, "webaudit", "geoip")
	}
	if x := getenv("XDG_DATA_HOME"); x != "" && absolute(x) {
		return join(x), nil
	}
	if goos == "windows" {
		if x := getenv("LOCALAPPDATA"); x != "" && absolute(x) {
			return join(x), nil
		}
		return "", fmt.Errorf("GeoIP directory: set absolute XDG_DATA_HOME or LOCALAPPDATA")
	}
	if x := getenv("HOME"); x != "" && absolute(x) {
		return join(path.Join(x, ".local/share")), nil
	}
	return "", fmt.Errorf("GeoIP directory: set absolute XDG_DATA_HOME or HOME")
}
func DefaultDir() (string, error) { return ResolveDir(runtime.GOOS, os.Getenv) }
