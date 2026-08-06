package wait

import (
	"context"
	"fmt"
	"time"
)

// WaitFor polls fn every interval until it returns true or timeout elapses. On
// timeout it surfaces the last error fn returned (if any) in the error message.
func WaitFor(ctx context.Context, timeout, interval time.Duration, fn func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		ok, err := fn()
		if ok {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			if last != nil {
				return fmt.Errorf("timed out after %s: %w", timeout, last)
			}
			return fmt.Errorf("timed out after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
