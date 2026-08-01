//go:build !linux
// +build !linux

package sctp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSocketConfigPreAssociationUnsupportedParity(t *testing.T) {
	valid := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
		DisableFragments:   SocketOptionEnable,
		FragmentInterleave: OptionalInt{Set: true, Value: SCTPFragmentInterleaveOther},
		RTOInfo:            &RtoInfo{Initial: 500, Max: 2000, Min: 200},
		DelayedSACK:        &DelayedSACKConfig{Delay: 200, Frequency: 2},
	})
	calls := []struct {
		name string
		call func() error
	}{
		{"Listen", func() error { _, err := valid.Listen("sctp", nil); return err }},
		{"Dial", func() error { _, err := valid.Dial("sctp", nil, nil); return err }},
		{"DialContext", func() error {
			_, err := valid.DialContext(context.Background(), "sctp", nil, nil)
			return err
		}},
		{"OpenEndpoint", func() error { _, err := valid.OpenEndpoint("sctp", nil); return err }},
		{"ListenEndpoint", func() error { _, err := valid.ListenEndpoint("sctp", nil); return err }},
	}
	for _, call := range calls {
		if err := call.call(); !errors.Is(err, ErrUnsupported) ||
			!errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s valid config = %v, want ErrUnsupported", call.name, err)
		}
	}

	invalid := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
		RTOInfo: &RtoInfo{AssocID: SCTPAssocID(SCTP_CURRENT_ASSOC)},
	})
	invalidCalls := []struct {
		name string
		call func() error
	}{
		{"Listen", func() error { _, err := invalid.Listen("sctp", nil); return err }},
		{"Dial", func() error { _, err := invalid.Dial("sctp", nil, nil); return err }},
		{"DialContext", func() error {
			_, err := invalid.DialContext(context.Background(), "sctp", nil, nil)
			return err
		}},
		{"OpenEndpoint", func() error { _, err := invalid.OpenEndpoint("sctp", nil); return err }},
		{"ListenEndpoint", func() error { _, err := invalid.ListenEndpoint("sctp", nil); return err }},
	}
	for _, call := range invalidCalls {
		err := call.call()
		if err == nil || !strings.Contains(err.Error(), "RTOInfo.AssocID") {
			t.Errorf("%s invalid config = %v, want portable RTOInfo validation error", call.name, err)
		}
		if errors.Is(err, ErrUnsupported) {
			t.Errorf("%s invalid config reached platform unsupported result: %v", call.name, err)
		}
	}
}
