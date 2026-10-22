// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2026 ReadyStack (this file)
// SPDX-License-Identifier: MPL-2.0

package xds

import (
	"regexp"
	"strings"
	"testing"

	envoy_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul/agent/structs"
)

// evalRBACPermission evaluates a permission the way Envoy's RBAC filter does for the rule
// types Consul's header rules generate: a header that occurs several times is matched as its
// values joined with ","; values are compared case-sensitively; regexes are full matches; a
// missing header matches only an inverted present-rule.
func evalRBACPermission(t *testing.T, p *envoy_rbac_v3.Permission, hdrs map[string][]string) bool {
	t.Helper()
	switch r := p.Rule.(type) {
	case *envoy_rbac_v3.Permission_Any:
		return r.Any
	case *envoy_rbac_v3.Permission_AndRules:
		for _, sub := range r.AndRules.Rules {
			if !evalRBACPermission(t, sub, hdrs) {
				return false
			}
		}
		return true
	case *envoy_rbac_v3.Permission_OrRules:
		for _, sub := range r.OrRules.Rules {
			if evalRBACPermission(t, sub, hdrs) {
				return true
			}
		}
		return false
	case *envoy_rbac_v3.Permission_NotRule:
		return !evalRBACPermission(t, r.NotRule, hdrs)
	case *envoy_rbac_v3.Permission_Header:
		return evalHeaderMatcher(t, r.Header, hdrs)
	}
	t.Fatalf("unexpected permission rule %T", p.Rule)
	return false
}

func evalHeaderMatcher(t *testing.T, m *envoy_route_v3.HeaderMatcher, hdrs map[string][]string) bool {
	t.Helper()
	vals, ok := hdrs[strings.ToLower(m.Name)]
	if !ok {
		_, present := m.HeaderMatchSpecifier.(*envoy_route_v3.HeaderMatcher_PresentMatch)
		return present && m.InvertMatch
	}
	v := strings.Join(vals, ",")
	var match bool
	switch s := m.HeaderMatchSpecifier.(type) {
	case *envoy_route_v3.HeaderMatcher_ExactMatch:
		match = v == s.ExactMatch
	case *envoy_route_v3.HeaderMatcher_PrefixMatch:
		match = strings.HasPrefix(v, s.PrefixMatch)
	case *envoy_route_v3.HeaderMatcher_SuffixMatch:
		match = strings.HasSuffix(v, s.SuffixMatch)
	case *envoy_route_v3.HeaderMatcher_PresentMatch:
		match = s.PresentMatch
	case *envoy_route_v3.HeaderMatcher_SafeRegexMatch:
		match = regexp.MustCompile(`^(?:` + s.SafeRegexMatch.Regex + `)$`).MatchString(v)
	default:
		t.Fatalf("unexpected header match %T", m.HeaderMatchSpecifier)
	}
	return match != m.InvertMatch
}

func TestHeaderRuleHardening_CVE_2024_10006(t *testing.T) {
	type req = map[string][]string
	type probe struct {
		name   string
		hdrs   req
		before bool // what Consul v1.16.4 generated
		after  bool // with the backport
	}
	cases := []struct {
		name   string
		action structs.IntentionAction
		hdr    structs.IntentionHTTPHeaderPermission
		probes []probe
	}{
		{
			name: "deny exact", action: structs.IntentionActionDeny,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-role", Exact: "admin"},
			probes: []probe{
				{"one value", req{"x-role": {"admin"}}, true, true},
				{"repeated header", req{"x-role": {"admin", "admin"}}, false, true},
				{"with another value", req{"x-role": {"user", "admin"}}, false, true},
				{"list in one header", req{"x-role": {"user, admin"}}, false, true},
				{"other case", req{"x-role": {"ADMIN"}}, false, true},
				{"other value", req{"x-role": {"user"}}, false, false},
				{"value that only contains it", req{"x-role": {"superadmin"}}, false, false},
				{"missing header", req{}, false, false},
			},
		},
		{
			name: "deny prefix", action: structs.IntentionActionDeny,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-path", Prefix: "/admin"},
			probes: []probe{
				{"one value", req{"x-path": {"/admin/x"}}, true, true},
				{"second value", req{"x-path": {"/ok", "/admin/x"}}, false, true},
				{"other case", req{"x-path": {"/ADMIN"}}, false, true},
				{"no value starts with it", req{"x-path": {"/ok/admin"}}, false, false},
			},
		},
		{
			name: "deny suffix", action: structs.IntentionActionDeny,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-host", Suffix: ".internal"},
			probes: []probe{
				{"one value", req{"x-host": {"db.internal"}}, true, true},
				{"first of two", req{"x-host": {"db.internal", "a.example"}}, false, true},
				{"other case", req{"x-host": {"DB.INTERNAL"}}, false, true},
				{"no value ends with it", req{"x-host": {"internal.example"}}, false, false},
			},
		},
		{
			name: "deny regex", action: structs.IntentionActionDeny,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-user", Regex: "adm[a-z]+"},
			probes: []probe{
				{"one value", req{"x-user": {"admin"}}, true, true},
				{"second value", req{"x-user": {"bob", "admin"}}, false, true},
				{"other case", req{"x-user": {"ADMIN"}}, false, true},
				{"no match", req{"x-user": {"bob"}}, false, false},
			},
		},
		{
			name: "allow prefix", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-version", Prefix: "v2"},
			probes: []probe{
				{"one value", req{"x-version": {"v2.1"}}, true, true},
				{"every value", req{"x-version": {"v2.1", "v2.3"}}, true, true},
				{"a second value that does not match", req{"x-version": {"v2.1", "v1"}}, true, false},
				{"other case", req{"x-version": {"V2"}}, false, false},
				{"missing header", req{}, false, false},
			},
		},
		{
			name: "allow suffix", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-origin", Suffix: ".internal"},
			probes: []probe{
				{"one value", req{"x-origin": {"a.internal"}}, true, true},
				{"a first value that does not match", req{"x-origin": {"evil.example", "a.internal"}}, true, false},
			},
		},
		{
			name: "allow regex", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-tenant", Regex: "t-[0-9]+(-[a-z]+)?"},
			probes: []probe{
				{"one value", req{"x-tenant": {"t-42"}}, true, true},
				{"two values (the whole joined value never matched; still refused)", req{"x-tenant": {"t-1", "t-2-eu"}}, false, false},
				{"a second value that does not match", req{"x-tenant": {"t-1", "root"}}, false, false},
				{"other case", req{"x-tenant": {"T-1"}}, false, false},
			},
		},
		{
			name: "allow regex that can match a comma", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-tenant", Regex: "t-.*"},
			probes: []probe{
				{"one value", req{"x-tenant": {"t-42"}}, true, true},
				{"a second value that does not match", req{"x-tenant": {"t-1", "root"}}, true, false},
				{"two matching values (only one value is accepted)", req{"x-tenant": {"t-1", "t-2"}}, true, false},
			},
		},
		{
			name: "allow exact (unchanged)", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-role", Exact: "reader"},
			probes: []probe{
				{"one value", req{"x-role": {"reader"}}, true, true},
				{"repeated header", req{"x-role": {"reader", "reader"}}, false, false},
				{"other case", req{"x-role": {"Reader"}}, false, false},
			},
		},
		{
			name: "allow unless (inverted exact)", action: structs.IntentionActionAllow,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-role", Exact: "admin", Invert: true},
			probes: []probe{
				{"other value", req{"x-role": {"user"}}, true, true},
				{"the value", req{"x-role": {"admin"}}, false, false},
				{"the value with another", req{"x-role": {"user", "admin"}}, true, false},
				{"other case", req{"x-role": {"Admin"}}, true, false},
			},
		},
		{
			name: "deny unless (inverted prefix)", action: structs.IntentionActionDeny,
			hdr: structs.IntentionHTTPHeaderPermission{Name: "x-version", Prefix: "v2", Invert: true},
			probes: []probe{
				{"the value", req{"x-version": {"v2.1"}}, false, false},
				{"other value", req{"x-version": {"v1"}}, true, true},
				{"the value and another", req{"x-version": {"v2.1", "v1"}}, false, true},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			perm := &structs.IntentionPermission{
				Action: tc.action,
				HTTP:   &structs.IntentionHTTPPermission{Header: []structs.IntentionHTTPHeaderPermission{tc.hdr}},
			}
			after := convertPermission(perm)
			before := headerRulePermission(upstreamHeaderMatcher(tc.hdr))
			for _, p := range tc.probes {
				require.Equal(t, p.before, evalRBACPermission(t, before, p.hdrs), "v1.16.4 matcher: %s", p.name)
				require.Equal(t, p.after, evalRBACPermission(t, after, p.hdrs), "hardened matcher: %s", p.name)
			}
		})
	}
}

// upstreamHeaderMatcher is the matcher Consul v1.16.4 generated for a header rule, unchanged.
func upstreamHeaderMatcher(hdr structs.IntentionHTTPHeaderPermission) *envoy_route_v3.HeaderMatcher {
	perm := &structs.IntentionPermission{
		Action: structs.IntentionActionAllow,
		HTTP:   &structs.IntentionHTTPPermission{Header: []structs.IntentionHTTPHeaderPermission{hdr}},
	}
	p := convertPermission(perm)
	// an allow-direction rule is wrapped as And(rule, per-value); the first is the v1.16.4 rule
	if and, ok := p.Rule.(*envoy_rbac_v3.Permission_AndRules); ok {
		p = and.AndRules.Rules[0]
	}
	if or, ok := p.Rule.(*envoy_rbac_v3.Permission_OrRules); ok {
		p = or.OrRules.Rules[0]
	}
	return p.Rule.(*envoy_rbac_v3.Permission_Header).Header
}

func TestHeaderRuleHardening_PresentUnchanged(t *testing.T) {
	for _, action := range []structs.IntentionAction{structs.IntentionActionAllow, structs.IntentionActionDeny} {
		for _, inv := range []bool{false, true} {
			hdr := structs.IntentionHTTPHeaderPermission{Name: "x-foo", Present: true, Invert: inv}
			p := convertPermission(&structs.IntentionPermission{Action: action,
				HTTP: &structs.IntentionHTTPPermission{Header: []structs.IntentionHTTPHeaderPermission{hdr}}})
			h, ok := p.Rule.(*envoy_rbac_v3.Permission_Header)
			require.True(t, ok, "present rule must stay a single header matcher")
			require.Equal(t, inv, h.Header.InvertMatch)
		}
	}
}

// A per-value expression that might exceed Envoy's RE2 program-size limit is not sent: the
// rule keeps its v1.16.4 matcher, so the listener is never rejected because of this fix.
func TestHeaderRuleHardening_ProgramSizeGuard(t *testing.T) {
	hdr := structs.IntentionHTTPHeaderPermission{Name: "x-name", Regex: `\pL+`}
	p := convertPermission(&structs.IntentionPermission{Action: structs.IntentionActionDeny,
		HTTP: &structs.IntentionHTTPPermission{Header: []structs.IntentionHTTPHeaderPermission{hdr}}})
	_, single := p.Rule.(*envoy_rbac_v3.Permission_Header)
	require.True(t, single)

	long := structs.IntentionHTTPHeaderPermission{Name: "x-token", Prefix: strings.Repeat("a", 40)}
	p = convertPermission(&structs.IntentionPermission{Action: structs.IntentionActionAllow,
		HTTP: &structs.IntentionHTTPPermission{Header: []structs.IntentionHTTPHeaderPermission{long}}})
	_, single = p.Rule.(*envoy_rbac_v3.Permission_Header)
	require.True(t, single, "every-value form of a 40-character prefix is estimated above the limit")
}

// The estimate is never below RE2's own program size. The sizes were measured with RE2
// (RE2::ProgramSize, UTF-8 mode, google-re2 1.1.20251105) on the expressions the builders produce.
func TestHeaderRuleHardening_EstimateCoversRE2(t *testing.T) {
	for _, tc := range re2MeasuredSizes {
		hdr := tc.hdr
		var patt string
		var est int
		if tc.every {
			patt, est = headerEveryValueRegex(hdr)
		} else {
			patt, est = headerAnyValueRegex(hdr)
		}
		require.Equal(t, tc.patt, patt)
		require.GreaterOrEqual(t, est, tc.re2, "estimate below RE2 for %q", patt)
	}
}

// RE2::ProgramSize of each expression, measured with the google-re2 1.1.20251105 Python binding (UTF-8 mode).
var re2MeasuredSizes = []struct {
	hdr   structs.IntentionHTTPHeaderPermission
	every bool
	patt  string
	re2   int
}{
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `admin`}, false, `(?i)(?:.*,)?[ \t]*admin[ \t]*(?:,.*)?`, 35},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `admin`}, false, `(?i)(?:.*,)?[ \t]*admin.*`, 30},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `admin`}, true, `[ \t]*admin[^,]*(?:,[ \t]*admin[^,]*)*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `admin`}, false, `(?i).*admin[ \t]*(?:,.*)?`, 30},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `admin`}, true, `[^,]*admin[ \t]*(?:,[^,]*admin[ \t]*)*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `v2`}, false, `(?i)(?:.*,)?[ \t]*v2[ \t]*(?:,.*)?`, 32},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `v2`}, false, `(?i)(?:.*,)?[ \t]*v2.*`, 27},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `v2`}, true, `[ \t]*v2[^,]*(?:,[ \t]*v2[^,]*)*`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `v2`}, false, `(?i).*v2[ \t]*(?:,.*)?`, 27},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `v2`}, true, `[^,]*v2[ \t]*(?:,[^,]*v2[ \t]*)*`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `/admin`}, false, `(?i)(?:.*,)?[ \t]*/admin[ \t]*(?:,.*)?`, 36},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `/admin`}, false, `(?i)(?:.*,)?[ \t]*/admin.*`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `/admin`}, true, `[ \t]*/admin[^,]*(?:,[ \t]*/admin[^,]*)*`, 39},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `/admin`}, false, `(?i).*/admin[ \t]*(?:,.*)?`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `/admin`}, true, `[^,]*/admin[ \t]*(?:,[^,]*/admin[ \t]*)*`, 39},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `.internal`}, false, `(?i)(?:.*,)?[ \t]*\.internal[ \t]*(?:,.*)?`, 39},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `.internal`}, false, `(?i)(?:.*,)?[ \t]*\.internal.*`, 34},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `.internal`}, true, `[ \t]*\.internal[^,]*(?:,[ \t]*\.internal[^,]*)*`, 45},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `.internal`}, false, `(?i).*\.internal[ \t]*(?:,.*)?`, 34},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `.internal`}, true, `[^,]*\.internal[ \t]*(?:,[^,]*\.internal[ \t]*)*`, 45},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `application/json`}, false, `(?i)(?:.*,)?[ \t]*application/json[ \t]*(?:,.*)?`, 48},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `application/json`}, false, `(?i)(?:.*,)?[ \t]*application/json.*`, 43},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `application/json`}, true, `[ \t]*application/json[^,]*(?:,[ \t]*application/json[^,]*)*`, 59},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `application/json`}, false, `(?i).*application/json[ \t]*(?:,.*)?`, 43},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `application/json`}, true, `[^,]*application/json[ \t]*(?:,[^,]*application/json[ \t]*)*`, 59},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `kiosk`}, false, `(?i)(?:.*,)?[ \t]*kiosk[ \t]*(?:,.*)?`, 43},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `kiosk`}, false, `(?i)(?:.*,)?[ \t]*kiosk.*`, 38},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `kiosk`}, true, `[ \t]*kiosk[^,]*(?:,[ \t]*kiosk[^,]*)*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `kiosk`}, false, `(?i).*kiosk[ \t]*(?:,.*)?`, 38},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `kiosk`}, true, `[^,]*kiosk[ \t]*(?:,[^,]*kiosk[ \t]*)*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `straße`}, false, `(?i)(?:.*,)?[ \t]*straße[ \t]*(?:,.*)?`, 42},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `straße`}, false, `(?i)(?:.*,)?[ \t]*straße.*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `straße`}, true, `[ \t]*straße[^,]*(?:,[ \t]*straße[^,]*)*`, 41},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `straße`}, false, `(?i).*straße[ \t]*(?:,.*)?`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `straße`}, true, `[^,]*straße[ \t]*(?:,[^,]*straße[ \t]*)*`, 41},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `ä-ünïcødé`}, false, `(?i)(?:.*,)?[ \t]*ä-ünïcødé[ \t]*(?:,.*)?`, 49},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `ä-ünïcødé`}, false, `(?i)(?:.*,)?[ \t]*ä-ünïcødé.*`, 44},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `ä-ünïcødé`}, true, `[ \t]*ä-ünïcødé[^,]*(?:,[ \t]*ä-ünïcødé[^,]*)*`, 55},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `ä-ünïcødé`}, false, `(?i).*ä-ünïcødé[ \t]*(?:,.*)?`, 44},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `ä-ünïcødé`}, true, `[^,]*ä-ünïcødé[ \t]*(?:,[^,]*ä-ünïcødé[ \t]*)*`, 55},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `s3cr3t-token-value-01`}, false, `(?i)(?:.*,)?[ \t]*s3cr3t-token-value-01[ \t]*(?:,.*)?`, 56},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `s3cr3t-token-value-01`}, false, `(?i)(?:.*,)?[ \t]*s3cr3t-token-value-01.*`, 51},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `s3cr3t-token-value-01`}, true, `[ \t]*s3cr3t-token-value-01[^,]*(?:,[ \t]*s3cr3t-token-value-01[^,]*)*`, 69},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `s3cr3t-token-value-01`}, false, `(?i).*s3cr3t-token-value-01[ \t]*(?:,.*)?`, 51},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `s3cr3t-token-value-01`}, true, `[^,]*s3cr3t-token-value-01[ \t]*(?:,[^,]*s3cr3t-token-value-01[ \t]*)*`, 69},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Exact: `SessionKey`}, false, `(?i)(?:.*,)?[ \t]*SessionKey[ \t]*(?:,.*)?`, 49},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `SessionKey`}, false, `(?i)(?:.*,)?[ \t]*SessionKey.*`, 44},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Prefix: `SessionKey`}, true, `[ \t]*SessionKey[^,]*(?:,[ \t]*SessionKey[^,]*)*`, 47},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `SessionKey`}, false, `(?i).*SessionKey[ \t]*(?:,.*)?`, 44},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Suffix: `SessionKey`}, true, `[^,]*SessionKey[ \t]*(?:,[^,]*SessionKey[ \t]*)*`, 47},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `adm[a-z]+`}, false, `(?i)(?:.*,)?[ \t]*(?:adm[a-z]+)[ \t]*(?:,.*)?`, 41},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `adm[a-z]+`}, true, `[ \t]*(?:adm[a-z]+)[ \t]*(?:,[ \t]*(?:adm[a-z]+)[ \t]*)*`, 27},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `t-.*`}, false, `(?i)(?:.*,)?[ \t]*(?:t-.*)[ \t]*(?:,.*)?`, 41},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `t-.*`}, true, `[^,]*`, 12},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `gi[rR]`}, false, `(?i)(?:.*,)?[ \t]*(?:gi[rR])[ \t]*(?:,.*)?`, 33},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `gi[rR]`}, true, `[ \t]*(?:gi[rR])[ \t]*(?:,[ \t]*(?:gi[rR])[ \t]*)*`, 21},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `v[0-9]+`}, false, `(?i)(?:.*,)?[ \t]*(?:v[0-9]+)[ \t]*(?:,.*)?`, 34},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `v[0-9]+`}, true, `[ \t]*(?:v[0-9]+)[ \t]*(?:,[ \t]*(?:v[0-9]+)[ \t]*)*`, 23},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `.*admin.*`}, false, `(?i)(?:.*,)?[ \t]*(?:.*admin.*)[ \t]*(?:,.*)?`, 53},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `.*admin.*`}, true, `[^,]*`, 12},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[a-z]+`}, false, `(?i)(?:.*,)?[ \t]*(?:[a-z]+)[ \t]*(?:,.*)?`, 39},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[a-z]+`}, true, `[ \t]*(?:[a-z]+)[ \t]*(?:,[ \t]*(?:[a-z]+)[ \t]*)*`, 23},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\d{3}-\d{4}`}, false, `(?i)(?:.*,)?[ \t]*(?:\d{3}-\d{4})[ \t]*(?:,.*)?`, 38},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\d{3}-\d{4}`}, true, `[ \t]*(?:\d{3}-\d{4})[ \t]*(?:,[ \t]*(?:\d{3}-\d{4})[ \t]*)*`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `(foo|bar|baz)-[0-9]{1,3}`}, false, `(?i)(?:.*,)?[ \t]*(?:(foo|bar|baz)-[0-9]{1,3})[ \t]*(?:,.*)?`, 45},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `(foo|bar|baz)-[0-9]{1,3}`}, true, `[ \t]*(?:(foo|bar|baz)-[0-9]{1,3})[ \t]*(?:,[ \t]*(?:(foo|bar|baz)-[0-9]{1,3})[ \t]*)*`, 45},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[^,]+`}, false, `(?i)(?:.*,)?[ \t]*(?:[^,]+)[ \t]*(?:,.*)?`, 41},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[^,]+`}, true, `[ \t]*(?:[^,]+)[ \t]*(?:,[ \t]*(?:[^,]+)[ \t]*)*`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\w+@example\.com`}, false, `(?i)(?:.*,)?[ \t]*(?:\w+@example\.com)[ \t]*(?:,.*)?`, 52},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\w+@example\.com`}, true, `[ \t]*(?:\w+@example\.com)[ \t]*(?:,[ \t]*(?:\w+@example\.com)[ \t]*)*`, 49},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `^admin$`}, false, `(?i)(?:.*,)?[ \t]*(?:^admin$)[ \t]*(?:,.*)?`, 37},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `^admin$`}, true, `[ \t]*(?:^admin$)[ \t]*(?:,[ \t]*(?:^admin$)[ \t]*)*`, 29},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `a{2,5}`}, false, `(?i)(?:.*,)?[ \t]*(?:a{2,5})[ \t]*(?:,.*)?`, 38},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `a{2,5}`}, true, `[ \t]*(?:a{2,5})[ \t]*(?:,[ \t]*(?:a{2,5})[ \t]*)*`, 31},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[A-Za-z0-9._%+-]+`}, false, `(?i)(?:.*,)?[ \t]*(?:[A-Za-z0-9._%+-]+)[ \t]*(?:,.*)?`, 44},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `[A-Za-z0-9._%+-]+`}, true, `[ \t]*(?:[A-Za-z0-9._%+-]+)[ \t]*(?:,[ \t]*(?:[A-Za-z0-9._%+-]+)[ \t]*)*`, 33},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\S+`}, false, `(?i)(?:.*,)?[ \t]*(?:\S+)[ \t]*(?:,.*)?`, 43},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `\S+`}, true, `[^,]*`, 12},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `x{3,}`}, false, `(?i)(?:.*,)?[ \t]*(?:x{3,})[ \t]*(?:,.*)?`, 35},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `x{3,}`}, true, `[ \t]*(?:x{3,})[ \t]*(?:,[ \t]*(?:x{3,})[ \t]*)*`, 25},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `(a|b|c|d)+`}, false, `(?i)(?:.*,)?[ \t]*(?:(a|b|c|d)+)[ \t]*(?:,.*)?`, 36},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `(a|b|c|d)+`}, true, `[ \t]*(?:(a|b|c|d)+)[ \t]*(?:,[ \t]*(?:(a|b|c|d)+)[ \t]*)*`, 27},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `.{0,4}`}, false, `(?i)(?:.*,)?[ \t]*(?:.{0,4})[ \t]*(?:,.*)?`, 66},
	{structs.IntentionHTTPHeaderPermission{Name: "x", Regex: `.{0,4}`}, true, `[^,]*`, 12},
}
