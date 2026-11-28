package cli

// Process exit codes (spec section 4.3).
const (
	ExitOK    = 0
	ExitGate  = 1
	ExitUsage = 2
	ExitInput = 3

	// ExitProbeRefused: a probe target was refused by the safety policy.
	ExitProbeRefused = 5
	ExitInternal     = 10
)

// exitError carries an exit code through cobra's error return.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErr(err error) error { return &exitError{code: ExitUsage, err: err} }

func inputErr(err error) error { return &exitError{code: ExitInput, err: err} }
