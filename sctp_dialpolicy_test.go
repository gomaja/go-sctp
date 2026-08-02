package sctp

import (
	"errors"
	"syscall"
	"testing"
)

func TestAbandonDialSocketUsesPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policy    DialAbandonPolicy
		wantAbort bool
		wantQuiet bool
		wantErr   error
		abortErr  error
		quietErr  error
	}{
		{
			name:      "abort",
			policy:    DialAbandonAbort,
			wantAbort: true,
			abortErr:  syscall.ECONNRESET,
			wantErr:   syscall.ECONNRESET,
		},
		{
			name:      "quiet",
			policy:    DialAbandonQuiet,
			wantQuiet: true,
			quietErr:  syscall.EBADF,
			wantErr:   syscall.EBADF,
		},
		{
			name:    "invalid",
			policy:  DialAbandonPolicy(99),
			wantErr: syscall.EINVAL,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var abortCalled, quietCalled bool
			err := abandonDialSocketUsing(
				123,
				tc.policy,
				func(fd int) error {
					abortCalled = true
					if fd != 123 {
						t.Fatalf("abort fd = %d, want 123", fd)
					}
					return tc.abortErr
				},
				func(fd int) error {
					quietCalled = true
					if fd != 123 {
						t.Fatalf("quiet close fd = %d, want 123", fd)
					}
					return tc.quietErr
				},
			)
			if abortCalled != tc.wantAbort {
				t.Fatalf("abort called = %v, want %v", abortCalled, tc.wantAbort)
			}
			if quietCalled != tc.wantQuiet {
				t.Fatalf("quiet close called = %v, want %v", quietCalled, tc.wantQuiet)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
