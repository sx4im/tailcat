// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"net/netip"
	"testing"
)

// TestAdvertisedEndpoints verifies that endpoints on a Tailscale
// interface are never advertised to peers (tailscale/tailcat#168): a
// peer that picks a Tailscale address as its direct path runs its
// WireGuard inside Tailscale's WireGuard, through a 1280-byte-MTU
// tunnel, where batched (GSO) sends from Linux mostly never arrive.
func TestAdvertisedEndpoints(t *testing.T) {
	lan4 := netip.MustParseAddrPort("192.168.1.2:41641")
	lan6 := netip.MustParseAddrPort("[fe80::1]:41641")
	stun := netip.MustParseAddrPort("203.0.113.7:41641")
	tsCGNAT := netip.MustParseAddrPort("100.64.0.9:41641")
	tsULA := netip.MustParseAddrPort("[fd7a:115c:a1e0::9]:41641")

	in := []netip.AddrPort{lan4, tsCGNAT, lan6, tsULA, stun}
	got := advertisedEndpoints(in)
	want := []netip.AddrPort{lan4, lan6, stun}
	if len(got) != len(want) {
		t.Fatalf("advertisedEndpoints(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("advertisedEndpoints(%v) = %v, want %v", in, got, want)
		}
	}
	// The input slice must not be modified.
	if in[1] != tsCGNAT || in[3] != tsULA {
		t.Fatalf("advertisedEndpoints modified its input: %v", in)
	}
}

func TestAdvertisedEndpointsAllTailscale(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("100.64.0.9:41641"),
		netip.MustParseAddrPort("[fd7a:115c:a1e0::9]:41641"),
	}
	if got := advertisedEndpoints(in); len(got) != 0 {
		t.Fatalf("advertisedEndpoints(%v) = %v, want empty (peer falls back to DERP)", in, got)
	}
}
