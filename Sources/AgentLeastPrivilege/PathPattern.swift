// PathPattern.swift
//
// A deliberately small path matcher. It models exactly the three shapes the
// Claude Code docs use for Read deny rules and sandbox filesystem rules, with
// the one behaviour that actually matters for a least-privilege policy:
// when a deny and an allow overlap, the *more specific* rule wins. That is why
// `allowRead: ["~/"]` with `denyRead: ["~/**/.env"]` keeps every `.env` blocked
// while the rest of home stays readable.

import Foundation

/// A read-path pattern, resolved against `Layout`.
public struct PathPattern: Sendable, Equatable, Codable {
    public let raw: String

    public init(_ raw: String) { self.raw = raw }

    /// Resolve `~/` to the fake home and `./` to the working directory.
    private var resolved: String {
        if raw == "~" || raw == "~/" { return Layout.home }
        if raw.hasPrefix("~/") { return Layout.home + "/" + String(raw.dropFirst(2)) }
        if raw == "." || raw == "./" { return Layout.workingDirectory }
        if raw.hasPrefix("./") { return Layout.workingDirectory + "/" + String(raw.dropFirst(2)) }
        return raw
    }

    /// True if this pattern matches `path`.
    public func matches(_ path: String) -> Bool {
        let p = resolved
        // Basename wildcard: `**/name` or a bare `name` — matches that
        // filename at any depth. Mirrors gitignore's bare-filename rule.
        if p.hasPrefix("**/") {
            let base = String(p.dropFirst(3))
            return !base.isEmpty && (path == base || path.hasSuffix("/" + base))
        }
        if !p.contains("/") {
            return path == p || path.hasSuffix("/" + p)
        }
        // Directory prefix, with or without a trailing `/**`.
        let prefix = p.hasSuffix("/**") ? String(p.dropLast(3)) : p
        return path == prefix || path.hasPrefix(prefix + "/")
    }

    /// How specific the match is. A higher score beats a lower one when a
    /// deny and an allow both match the same path. Chosen so the three
    /// documented overlap cases resolve correctly.
    public func specificity(matching path: String) -> Int {
        guard matches(path) else { return 0 }
        let p = resolved
        if p.hasPrefix("**/") { return 900 }   // pins a filename, beats any dir prefix
        if !p.contains("/") { return 900 }
        // Directory/path prefix: deeper is more specific, so a narrower allow
        // re-opens a broader deny, and a deeper deny holds inside a broader allow.
        let prefix = p.hasSuffix("/**") ? String(p.dropLast(3)) : p
        return prefix.split(separator: "/").count
    }
}

/// A set of allow/deny read rules evaluated with "most specific wins,
/// deny breaks ties". Used for both the permission layer and the sandbox
/// filesystem layer.
public struct ReadRuleSet: Sendable, Equatable, Codable {
    public var allow: [PathPattern]
    public var deny: [PathPattern]

    public init(allow: [PathPattern] = [], deny: [PathPattern] = []) {
        self.allow = allow
        self.deny = deny
    }

    public enum Outcome: Sendable, Equatable { case allowed, denied, noOpinion }

    /// Decide a single path against the rule set.
    public func decide(_ path: String) -> Outcome {
        let topDeny = deny.map { $0.specificity(matching: path) }.max() ?? 0
        let topAllow = allow.map { $0.specificity(matching: path) }.max() ?? 0
        if topDeny == 0 && topAllow == 0 { return .noOpinion }
        if topDeny >= topAllow && topDeny > 0 { return .denied } // deny wins ties
        return .allowed
    }
}
