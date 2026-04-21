package internal

import (
	"context"
	"errors"
	"net"
)

// ErrBlockedDestination is returned when a proxy/forwarder dial target is
// rejected because it resolves to a private, loopback, link-local,
// multicast, or otherwise non-routable address and the operator has not
// explicitly opted in via --allow-private-destinations.
var ErrBlockedDestination = errors.New("destination address is in a blocked range (loopback/private/link-local/multicast); pass --allow-private-destinations to override")

// IsBlockedIP reports whether the given IP belongs to a range that should
// not be reachable through a public-facing proxy or port forwarder by
// default. This includes:
//
//   - Loopback (127.0.0.0/8, ::1)
//   - RFC1918 / unique-local (10/8, 172.16/12, 192.168/16, fc00::/7)
//   - Link-local unicast and multicast (169.254/16, fe80::/10, 224.0.0.0/24, ff02::/16)
//   - Multicast (any)
//   - Unspecified (0.0.0.0, ::)
//   - Cloud metadata service (169.254.169.254)
//
// The intent is to prevent accidental SSRF through the local proxy ports
// — e.g. an attacker on the LAN reaching the host's own services or the
// IMDS via the WARP-bound proxy.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// 169.254.169.254 (cloud metadata) — already covered by IsLinkLocalUnicast,
	// but we keep an explicit check for clarity and for any future drift.
	if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 && v4[2] == 169 && v4[3] == 254 {
		return true
	}
	return false
}

// CheckHostAllowed resolves host (which may be a hostname or an IP literal)
// using the supplied resolver and returns nil if every resolved address is
// allowed. If resolver is nil and host is not an IP literal, the function
// returns nil and leaves enforcement to the dial-time check on the caller
// side. If allowPrivate is true, no filtering is performed.
func CheckHostAllowed(ctx context.Context, host string, resolver *net.Resolver, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	if host == "" {
		return errors.New("empty destination host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return ErrBlockedDestination
		}
		return nil
	}
	if resolver == nil {
		// Best-effort: no resolver supplied; let the dial-time check catch it.
		return nil
	}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return ErrBlockedDestination
		}
	}
	return nil
}
