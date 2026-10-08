package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner is the process boundary for OS adapters; tests never change the host.
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type Commands struct{}
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return "system command failed" }
func status(err error) int {
	var e *StatusError
	if errors.As(err, &e) {
		return e.Code
	}
	return -1
}

type boundedOutput struct {
	data  bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.data.Len()+len(p) > b.limit {
		return 0, errors.New("system command output limit exceeded")
	}
	_, err := b.data.Write(p)
	return n, err
}

func (Commands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var path string
	if filepath.IsAbs(name) {
		if name != "/etc/init.d/nx-syncd" {
			return nil, errors.New("unsupported absolute system command")
		}
		path = name
	} else {
		if strings.ContainsAny(name, "/\\") {
			return nil, errors.New("invalid command name")
		}
		for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			candidate := filepath.Join(directory, name)
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				path = candidate
				break
			}
		}
		if path == "" {
			return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output := &boundedOutput{limit: 64 << 10}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return output.data.Bytes(), &StatusError{Code: exit.ExitCode()}
		}
		return nil, err
	}
	return output.data.Bytes(), nil
}
