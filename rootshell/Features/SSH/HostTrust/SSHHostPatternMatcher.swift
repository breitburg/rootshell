//
//  SSHHostPatternMatcher.swift
//  rootshell
//
//  OpenSSH-style glob matching for hostnames, ported from OpenSSH's match.c
//  `match_pattern` / `match_pattern_list`. Used for two things:
//    1. Scoping a configured host CA to hostnames (its `hostPatterns`,
//       mirroring `@cert-authority *.example.com` lines).
//    2. Matching a connection hostname against a host certificate's
//       `validPrincipals` (NIOSSH's own `validate` does exact-match only, so we
//       pre-match here to support wildcard principals like `*.dc1.example.com`).
//

import Foundation

enum SSHHostPatternMatcher {
    /// True if `host` matches the given patterns, following OpenSSH
    /// `match_pattern_list` semantics. Each entry may itself be a comma-separated
    /// list of patterns. Matching is case-insensitive (hostnames are
    /// case-insensitive). An empty pattern list never matches.
    ///
    /// A pattern prefixed with `!` is a negation: if the host matches any
    /// negated pattern, the result is `false` regardless of positive matches
    /// (an explicit exclusion always wins). Otherwise the host matches when it
    /// matches at least one positive pattern. This lets an admin scope a CA with
    /// e.g. `*.example.com,!bastion.example.com` and have `bastion.example.com`
    /// correctly excluded.
    nonisolated static func matches(host: String, patterns: [String]) -> Bool {
        let normalizedHost = host.lowercased()
        var positiveMatch = false
        for entry in patterns {
            for rawPattern in entry.split(separator: ",", omittingEmptySubsequences: true) {
                var pattern = rawPattern.trimmingCharacters(in: .whitespaces).lowercased()
                if pattern.isEmpty { continue }

                var negated = false
                if pattern.hasPrefix("!") {
                    negated = true
                    pattern.removeFirst()
                    pattern = pattern.trimmingCharacters(in: .whitespaces)
                    if pattern.isEmpty { continue }
                }

                if matchGlob(normalizedHost, pattern: pattern) {
                    // An explicit negated match excludes the host outright — and
                    // we must scan the whole list (no early return on a positive)
                    // so a negation anywhere still wins.
                    if negated { return false }
                    positiveMatch = true
                }
            }
        }
        return positiveMatch
    }

    /// Single-pattern glob match with OpenSSH semantics: `*` matches any run of
    /// characters (including none), `?` matches exactly one character. No other
    /// metacharacters are special. Iterative with backtracking (no recursion,
    /// so it can't blow the stack on adversarial input).
    nonisolated static func matchGlob(_ string: String, pattern: String) -> Bool {
        let str = Array(string)
        let pat = Array(pattern)
        var si = 0
        var pi = 0
        var starIndex = -1
        var matchIndex = 0

        while si < str.count {
            if pi < pat.count, pat[pi] == "?" || pat[pi] == str[si] {
                si += 1
                pi += 1
            } else if pi < pat.count, pat[pi] == "*" {
                starIndex = pi
                matchIndex = si
                pi += 1
            } else if starIndex != -1 {
                pi = starIndex + 1
                matchIndex += 1
                si = matchIndex
            } else {
                return false
            }
        }

        while pi < pat.count, pat[pi] == "*" {
            pi += 1
        }
        return pi == pat.count
    }
}
