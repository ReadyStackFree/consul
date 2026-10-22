// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2026 ReadyStack (this file)
// SPDX-License-Identifier: MPL-2.0

package xds

// ReadyStack security backport for CVE-2024-10006 / GHSA-5c4w-8hhh-3c3h (HashiCorp
// HCSEC-2024-23, "Consul L7 Intentions vulnerable to headers bypass") on Consul v1.16.4, the
// last MPL-2.0 release. HashiCorp fixed it only in BUSL-1.1 releases (1.20.1 and later); this
// fix was written independently from the public advisory and Envoy's documented
// header-matching behaviour, and contains no code from those releases.
//
// The advisory: header rules in L7 intentions could be bypassed through "multiple headers
// and/or case-sensitivity". When a request carries a header more than once, Envoy's RBAC
// filter matches the rule against all of the values joined with ","; and it compares values
// case-sensitively. So a deny rule `x-role exact admin` did not match a request that sent
// `x-role: admin` twice ("admin,admin") or together with another value ("user,admin"), nor
// one that sent `x-role: ADMIN`; an application that reads one of the values, or compares
// them case-insensitively, then served a request the intention meant to refuse. The same
// gap let a request through an allow rule such as `x-version prefix v2` with a second,
// non-matching value ("v2,v1").
//
// The fix makes every header rule fail closed, without changing the intentions API:
//
//   - A rule whose match leads to DENIAL (a deny permission, or an allow permission with
//     Invert) also matches when ANY one of the comma-separated values satisfies it, compared
//     case-insensitively: Or(the rule as before, that per-value match).
//   - A rule whose match leads to ACCESS (an allow permission, or a deny permission with
//     Invert) matches only when EVERY comma-separated value satisfies it (case-sensitive, as
//     before): And(the rule as before, that per-value match).
//
// A rule therefore never matches fewer requests than before in the deny direction, nor more
// requests than before in the allow direction. Present rules are unchanged (presence does not
// depend on the values). An exact rule in the allow direction is unchanged: one comma-free
// value can never equal several joined values. A prefix or suffix that itself contains a
// comma cannot be split per value and keeps the old matching. A regular expression in the
// allow direction that can itself match a comma cannot be split per value either: it then
// matches only a header with a single value that contains no comma.
//
// Envoy refuses a regular expression whose RE2 program is larger than its limit (runtime
// re2.max_program_size.error_level, 100 by default) and would then reject the whole
// listener. The per-value expressions are built only when an upper estimate of their RE2
// program size stays within rbacHeaderMaxProgramSize; otherwise the rule keeps the old
// matching (as before this fix) rather than risk the listener. The estimate is exact enough
// for literal values (measured overheads of the fixed parts plus the value's own cost) and
// deliberately pessimistic for a rule's own regular expression.

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"

	envoy_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/hashicorp/consul/agent/structs"
)

// rbacHeaderMaxProgramSize is the largest estimated RE2 program size of a per-value header
// expression this fix will send to Envoy (Envoy's default limit is 100).
const rbacHeaderMaxProgramSize = 95

// RE2 program sizes (RE2::ProgramSize, UTF-8 mode) of the fixed parts of the per-value
// expressions below, measured with RE2 for short values and rounded up: an expression's size
// is at most its overhead plus its value's cost (twice that for the every-value forms).
const (
	re2AnyExactOverhead   = 31 // (?i) before value after
	re2AnyAffixOverhead   = 26 // (?i) before value .*   /   (?i) .* value after
	re2EveryAffixOverhead = 28 // one(,one)*, one = [ \t]* value [^,]*   (or its mirror)
	re2AnyRegexOverhead   = 30 // (?i) before (?:re) after
	re2EveryRegexOverhead = 14 // one(,one)*, one = [ \t]*(?:re)[ \t]*
	re2SingleValueSize    = 15 // [^,]*
)

const (
	headerValuesBefore = `(?:.*,)?[ \t]*` // any earlier values, then this value's leading spaces
	headerValuesAfter  = `[ \t]*(?:,.*)?` // this value's trailing spaces, then any later values
)

func headerRulePermission(m *envoy_route_v3.HeaderMatcher) *envoy_rbac_v3.Permission {
	return &envoy_rbac_v3.Permission{
		Rule: &envoy_rbac_v3.Permission_Header{Header: m},
	}
}

// hardenHeaderPermission returns the RBAC permission for one header rule of an L7 intention
// permission. matcher is the rule as Consul has always generated it; isDeny says whether the
// permission's action is deny.
func hardenHeaderPermission(hdr structs.IntentionHTTPHeaderPermission, matcher *envoy_route_v3.HeaderMatcher, isDeny bool) *envoy_rbac_v3.Permission {
	base := headerRulePermission(matcher)
	if hdr.Present {
		return base
	}

	// With Invert the permission matches when the value does NOT satisfy the rule, so the
	// value test must be widened for an inverted allow and narrowed for an inverted deny.
	widen := isDeny != hdr.Invert
	var (
		patt string
		size int
	)
	if widen {
		patt, size = headerAnyValueRegex(hdr)
	} else {
		patt, size = headerEveryValueRegex(hdr)
	}
	if patt == "" || size > rbacHeaderMaxProgramSize {
		return base
	}

	perValue := headerRulePermission(&envoy_route_v3.HeaderMatcher{
		Name: hdr.Name,
		HeaderMatchSpecifier: &envoy_route_v3.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: makeEnvoyRegexMatch(patt),
		},
		// Same name and same inversion as the rule itself: a request without the header gets
		// the same answer from both matchers, so its outcome does not change.
		InvertMatch: hdr.Invert,
	})

	// Deny: either matcher is enough (broader). Allow: both must match (narrower). With Invert
	// the per-value test was chosen the other way round above, so the same combination holds.
	if isDeny {
		return orPermissions([]*envoy_rbac_v3.Permission{base, perValue})
	}
	return andPermissions([]*envoy_rbac_v3.Permission{base, perValue})
}

// headerAnyValueRegex: some comma-separated value satisfies the rule, case-insensitively;
// and an upper estimate of its RE2 program size. The cases are in the order convertPermission
// picks the rule's match type.
func headerAnyValueRegex(hdr structs.IntentionHTTPHeaderPermission) (string, int) {
	switch {
	case hdr.Exact != "":
		return `(?i)` + headerValuesBefore + regexp.QuoteMeta(hdr.Exact) + headerValuesAfter,
			re2AnyExactOverhead + re2LiteralCost(hdr.Exact, true)
	case hdr.Regex != "":
		return `(?i)` + headerValuesBefore + `(?:` + hdr.Regex + `)` + headerValuesAfter,
			re2AnyRegexOverhead + estimateRE2ProgramSize(`(?i)(?:`+hdr.Regex+`)`)
	case hdr.Prefix != "":
		return `(?i)` + headerValuesBefore + regexp.QuoteMeta(hdr.Prefix) + `.*`,
			re2AnyAffixOverhead + re2LiteralCost(hdr.Prefix, true)
	case hdr.Suffix != "":
		return `(?i).*` + regexp.QuoteMeta(hdr.Suffix) + headerValuesAfter,
			re2AnyAffixOverhead + re2LiteralCost(hdr.Suffix, true)
	}
	return "", 0
}

// headerEveryValueRegex: every comma-separated value satisfies the rule (case-sensitive); and
// an upper estimate of its RE2 program size.
func headerEveryValueRegex(hdr structs.IntentionHTTPHeaderPermission) (string, int) {
	every := func(one string) string { return one + `(?:,` + one + `)*` }
	switch {
	case hdr.Exact != "":
		return "", 0 // the rule as before is already exact on the whole (joined) value
	case hdr.Regex != "":
		if re2CanMatchRune(hdr.Regex, ',') {
			// "t-.*" also matches "t-1,root" as one value: splitting cannot be trusted, so
			// accept only a single value with no comma.
			return `[^,]*`, re2SingleValueSize
		}
		return every(`[ \t]*(?:` + hdr.Regex + `)[ \t]*`),
			re2EveryRegexOverhead + 2*estimateRE2ProgramSize(hdr.Regex)
	case hdr.Prefix != "":
		if strings.Contains(hdr.Prefix, ",") {
			return "", 0
		}
		return every(`[ \t]*` + regexp.QuoteMeta(hdr.Prefix) + `[^,]*`),
			re2EveryAffixOverhead + 2*re2LiteralCost(hdr.Prefix, false)
	case hdr.Suffix != "":
		if strings.Contains(hdr.Suffix, ",") {
			return "", 0
		}
		return every(`[^,]*` + regexp.QuoteMeta(hdr.Suffix) + `[ \t]*`),
			re2EveryAffixOverhead + 2*re2LiteralCost(hdr.Suffix, false)
	}
	return "", 0
}

// re2CanMatchRune reports whether some string the expression matches contains c (true when
// it does not parse).
func re2CanMatchRune(patt string, c rune) bool {
	re, err := syntax.Parse(patt, syntax.Perl)
	if err != nil {
		return true
	}
	var can func(*syntax.Regexp) bool
	can = func(re *syntax.Regexp) bool {
		switch re.Op {
		case syntax.OpLiteral:
			for _, r := range re.Rune {
				if r == c || (re.Flags&syntax.FoldCase != 0 && unicode.SimpleFold(r) == c) {
					return true
				}
			}
		case syntax.OpCharClass:
			for i := 0; i+1 < len(re.Rune); i += 2 {
				if re.Rune[i] <= c && c <= re.Rune[i+1] {
					return true
				}
			}
		case syntax.OpAnyChar:
			return true
		case syntax.OpAnyCharNotNL:
			return c != '\n'
		}
		for _, sub := range re.Sub {
			if can(sub) {
				return true
			}
		}
		return false
	}
	return can(re)
}

// re2LiteralCost: what a literal string costs in an RE2 program (one instruction per byte;
// folded, one per ASCII letter pair plus each non-ASCII case variant's bytes).
func re2LiteralCost(lit string, fold bool) int {
	n := 0
	for _, r := range lit {
		n += re2RuneCost(r, fold)
	}
	return n
}

// estimateRE2ProgramSize returns an upper estimate of the size of the RE2 program (UTF-8
// mode, as Envoy compiles it) for patt, or a value above any limit when patt does not parse.
// It walks Go's parse of the expression (the RE2 syntax) and charges each node what RE2's
// compiler emits for it at most: UTF-8 byte-range sequences for character classes (without
// RE2's suffix sharing), case-folded variants, repetitions expanded. Checked against RE2's own
// RE2::ProgramSize() on a corpus of header rules (never below it).
func estimateRE2ProgramSize(patt string) int {
	re, err := syntax.Parse(patt, syntax.Perl)
	if err != nil {
		return 1 << 20
	}
	return 4 + re2NodeCost(re.Simplify())
}

func re2NodeCost(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch:
		return 1
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += re2RuneCost(r, re.Flags&syntax.FoldCase != 0)
		}
		return n
	case syntax.OpCharClass:
		return re2ClassCost(re.Rune)
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 9 // RE2 compiles "." to 8 instructions (measured), shared UTF-8 suffixes
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 1
	case syntax.OpCapture:
		return 2 + re2NodeCost(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return 2 + re2NodeCost(re.Sub[0])
	case syntax.OpRepeat:
		n := re.Max
		if n < 0 { // x{min,}: min copies and a star
			n = re.Min + 1
		}
		if n < 1 {
			n = 1
		}
		return n * (2 + re2NodeCost(re.Sub[0]))
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			n += re2NodeCost(s)
		}
		return n
	case syntax.OpAlternate:
		n := len(re.Sub)
		for _, s := range re.Sub {
			n += re2NodeCost(s)
		}
		return n
	}
	return 1 << 20 // a node this estimate does not know: refuse
}

// re2RuneCost: one literal character; with case folding, each of its case variants (an ASCII
// pair is one folded byte range; k also folds to U+212A KELVIN SIGN, s to U+017F, ...).
func re2RuneCost(r rune, fold bool) int {
	if !fold {
		return utf8.RuneLen(r)
	}
	n, ascii := 0, false
	for f := r; ; {
		if f < utf8.RuneSelf {
			ascii = true
		} else {
			n += 1 + utf8.RuneLen(f)
		}
		f = unicode.SimpleFold(f)
		if f == r {
			break
		}
	}
	if ascii {
		n++
	}
	return n
}

// re2ClassCost: a character class (Go's sorted [lo, hi] pairs) as RE2 compiles it in UTF-8
// mode: an alternation of byte-range sequences whose continuation-byte suffixes are shared.
func re2ClassCost(ranges []rune) int {
	type node struct {
		lo, hi byte
		next   int
	}
	shared := map[node]int{}
	insts, seqs := 0, 0
	for i := 0; i+1 < len(ranges); i += 2 {
		for _, seq := range utf8Sequences(ranges[i], ranges[i+1]) {
			seqs++
			next := 0
			for j := len(seq[0]) - 1; j >= 1; j-- {
				k := node{seq[0][j], seq[1][j], next}
				id, ok := shared[k]
				if !ok {
					insts++
					id = insts
					shared[k] = id
				}
				next = id
			}
			insts++ // the leading byte range
		}
	}
	return insts + seqs
}

// utf8Sequences splits [lo, hi] into ranges whose UTF-8 encodings differ only byte-wise
// within each position (the split RE2 and other byte-level regex compilers use); each result
// is the encoding of its first and last rune.
func utf8Sequences(lo, hi rune) [][2][]byte {
	type rng struct{ lo, hi rune }
	var out [][2][]byte
	stack := []rng{{lo, hi}}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
	split:
		for r.lo <= r.hi {
			// never across the surrogate gap or an encoded-length boundary
			for _, b := range [...]rune{0xD7FF, 0x7F, 0x7FF, 0xFFFF} {
				if r.lo <= b && r.hi > b {
					stack = append(stack, rng{b + 1, r.hi})
					r.hi = b
				}
			}
			if r.lo >= 0xD800 && r.lo <= 0xDFFF {
				if r.hi <= 0xDFFF {
					break // surrogates only: not encodable
				}
				r.lo = 0xE000
				continue
			}
			for i := 1; i < utf8.UTFMax; i++ {
				m := rune(1)<<(6*uint(i)) - 1
				if r.lo&^m != r.hi&^m {
					if r.lo&m != 0 {
						stack = append(stack, rng{(r.lo | m) + 1, r.hi})
						r.hi = r.lo | m
						continue split
					}
					if r.hi&m != m {
						stack = append(stack, rng{r.hi &^ m, r.hi})
						r.hi = (r.hi &^ m) - 1
						continue split
					}
				}
			}
			a, b := make([]byte, utf8.UTFMax), make([]byte, utf8.UTFMax)
			na, nb := utf8.EncodeRune(a, r.lo), utf8.EncodeRune(b, r.hi)
			if na == nb {
				out = append(out, [2][]byte{a[:na], b[:nb]})
			}
			break
		}
	}
	return out
}
