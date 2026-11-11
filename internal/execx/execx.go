// Package execx runs external diagnostic commands with a timeout and records
// their output for the report appendix.
package execx

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// Output is a captured command run.
type Output struct {
	Command  string `json:"command"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

// MaxOutput caps captured output size per command.
const MaxOutput = 64 * 1024

// Run executes name with args, returning combined stdout/stderr.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) Output {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	o := Output{
		Command:  strings.TrimSpace(name + " " + strings.Join(args, " ")),
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}
	out := buf.String()
	if len(out) > MaxOutput {
		out = out[:MaxOutput] + "\n…[truncated]"
	}
	o.Output = strings.TrimRight(strings.ReplaceAll(out, "\r\n", "\n"), "\n ")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			o.Error = "timed out after " + timeout.String()
		} else {
			o.Error = err.Error()
		}
	}
	return o
}

// Exists reports whether a command is on PATH.
func Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
