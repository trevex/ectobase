// Package exec wraps os/exec with bounded stderr capture and good error context.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// ExecError carries the command line, exit code, and captured stderr of a failed
// subprocess so callers get an actionable message instead of "exit status 1".
type ExecError struct {
	Argv     []string
	ExitCode int
	Stderr   string
	Err      error
}

func (e *ExecError) Error() string {
	msg := fmt.Sprintf("exec %s: exit %d", strings.Join(e.Argv, " "), e.ExitCode)
	if s := strings.TrimSpace(e.Stderr); s != "" {
		msg += ": " + s
	}
	return msg
}

func (e *ExecError) Unwrap() error { return e.Err }

func execErr(argv []string, stderr string, err error) *ExecError {
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	return &ExecError{Argv: argv, ExitCode: code, Stderr: stderr, Err: err}
}

// tailWriter keeps only the last max bytes written — bounds stderr capture so a
// chatty subprocess can't grow an error string without limit.
type tailWriter struct {
	max int
	buf []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.max {
		w.buf = w.buf[len(w.buf)-w.max:]
	}
	return len(p), nil
}

const stderrTailMax = 16 << 10 // 16 KiB of stderr retained for error messages

// exec1 runs name+args. stdin (if non-empty) is fed in; if captureStdout, stdout
// is returned, else streamed to os.Stdout; stderr is always captured (bounded)
// and, when teeStderr, also streamed to os.Stderr. Failures wrap *ExecError.
func exec1(ctx context.Context, stdin string, captureStdout, teeStderr bool, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	slog.Debug("exec", "cmd", strings.Join(argv, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	tail := &tailWriter{max: stderrTailMax}
	if captureStdout {
		cmd.Stdout = &out
	} else {
		cmd.Stdout = os.Stdout
	}
	if teeStderr {
		cmd.Stderr = io.MultiWriter(os.Stderr, tail)
	} else {
		cmd.Stderr = tail
	}
	if err := cmd.Run(); err != nil {
		return out.Bytes(), execErr(argv, string(tail.buf), err)
	}
	return out.Bytes(), nil
}

// Run executes name+args, streaming stdout/stderr to the process's own, and
// wraps any failure in *ExecError (stderr is also teed into the error).
func Run(ctx context.Context, name string, args ...string) error {
	_, err := exec1(ctx, "", false, true, name, args...)
	return err
}

// Output executes name+args and returns stdout; failures wrap stderr + exit code.
func Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec1(ctx, "", true, false, name, args...)
}

// runStdin runs name+args feeding stdin, wrapping failures in *ExecError.
func runStdin(ctx context.Context, stdin string, name string, args ...string) error {
	_, err := exec1(ctx, stdin, false, true, name, args...)
	return err
}

// OutputStdin runs name+args feeding stdin, returning stdout; wraps failures.
func OutputStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	return exec1(ctx, stdin, true, false, name, args...)
}

// OutputStr is Output returning a string; convenient for text command output.
func OutputStr(ctx context.Context, name string, args ...string) (string, error) {
	out, err := Output(ctx, name, args...)
	return string(out), err
}
