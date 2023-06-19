// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !js && !wasip1

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
	"tailscale.com/version/distro"
)

func init() {
	stateFileFunc = stateFileUnix
}

func statePath() string {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/mirage/miraged.state"
	case "freebsd", "openbsd":
		return "/var/db/mirage/miraged.state"
	case "darwin":
		return "/Library/Mirage/miraged.state"
	default:
		return ""
	}
}

func stateFileUnix() string {
	if distro.Get() == distro.Gokrazy {
		return "/perm/miraged/miraged.state"
	}
	path := statePath()
	if path == "" {
		return ""
	}

	try := path
	for i := 0; i < 3; i++ { // check writability of the file, /var/lib/tailscale, and /var/lib
		err := unix.Access(try, unix.O_RDWR)
		if err == nil {
			return path
		}
		try = filepath.Dir(try)
	}

	if os.Getuid() == 0 {
		return ""
	}

	// For non-root users, fall back to $XDG_DATA_HOME/tailscale/*.
	return filepath.Join(xdgDataHome(), "mirage", "miraged.state")
}

func xdgDataHome() string {
	if e := os.Getenv("XDG_DATA_HOME"); e != "" {
		return e
	}
	return filepath.Join(os.Getenv("HOME"), ".local/share")
}

func ensureStateDirPerms(dir string) error {
	if filepath.Base(dir) != "mirage" {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("expected %q to be a directory; is %v", dir, fi.Mode())
	}
	const perm = 0700
	if fi.Mode().Perm() == perm {
		// Already correct.
		return nil
	}
	return os.Chmod(dir, perm)
}

// LegacyStateFilePath is not applicable to UNIX; it is just stubbed out.
func LegacyStateFilePath() string {
	return ""
}
