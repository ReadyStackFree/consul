// Copyright 2016 The CoreDNS Authors
// SPDX-License-Identifier: Apache-2.0
//
// Vendored verbatim (function bodies unchanged) from CoreDNS
// plugin/pkg/dnsutil/reverse.go @ v1.10.1 so Consul does not link the full
// github.com/coredns/coredns module (it used only ExtractAddressFromReverse).
// Removing the dependency eliminates coredns from the build SBOM. Apache-2.0.
package dnsutil

import (
	"net"
	"strings"
)

// ExtractAddressFromReverse turns a standard PTR reverse record name into an IP.
func ExtractAddressFromReverse(reverseName string) string {
	search := ""
	f := reverse
	switch {
	case strings.HasSuffix(reverseName, IP4arpa):
		search = strings.TrimSuffix(reverseName, IP4arpa)
	case strings.HasSuffix(reverseName, IP6arpa):
		search = strings.TrimSuffix(reverseName, IP6arpa)
		f = reverse6
	default:
		return ""
	}
	return f(strings.Split(search, "."))
}

func reverse(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	ip := net.ParseIP(strings.Join(slice, ".")).To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

func reverse6(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice6 := []string{}
	for i := 0; i < len(slice)/4; i++ {
		slice6 = append(slice6, strings.Join(slice[i*4:i*4+4], ""))
	}
	ip := net.ParseIP(strings.Join(slice6, ":")).To16()
	if ip == nil {
		return ""
	}
	return ip.String()
}

const (
	IP4arpa = ".in-addr.arpa."
	IP6arpa = ".ip6.arpa."
)
