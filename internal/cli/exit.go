package cli

import "fmt"

// ExitError carries process exit code for command-specific failures.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("exit with code %d", e.Code)
	}
	return e.Message
}
