//go:build hid_diagnostics && (darwin || linux)

package client_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func clientDiagnosticSecureInputAvailable() bool { return true }
func readClientDiagnosticSecureFile(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) || limit < 1 || limit > 4096 {
		return nil, errors.New("client diagnostic secure input requires an absolute file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, errClientDiagnosticFileAbsent
	}
	if err != nil {
		return nil, errors.New("client diagnostic secure input could not be opened safely")
	}
	file := os.NewFile(uintptr(fd), "client-diagnostic-input")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, errors.New("client diagnostic secure input metadata unavailable")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Size < 1 || stat.Size > int64(limit) {
		return nil, errors.New("client diagnostic secure input must be owner-only 0600 regular bounded file")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		for index := range data {
			data[index] = 0
		}
		return nil, errors.New("client diagnostic secure input read failed")
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || len(data) != int(stat.Size) || after.Dev != stat.Dev || after.Ino != stat.Ino || after.Nlink != stat.Nlink || after.Size != stat.Size || after.Mode != stat.Mode || after.Uid != stat.Uid || after.Gid != stat.Gid || after.Mtim != stat.Mtim || after.Ctim != stat.Ctim {
		for index := range data {
			data[index] = 0
		}
		return nil, errors.New("client diagnostic secure input changed during read")
	}
	return data, nil
}
