// Policy.swift
//
// The three independent layers a lead actually configures, plus the host
// Full Disk Access state that sits underneath all of them. None of the three
// is a superset of another: that is why a least-privilege policy has to name
// all three, and why picking one leaves a path open.

import Foundation

/// The permission layer: Read/Edit deny rules and the
/// `blockReadsOutsideWorkingDirectories` switch. Applies to Claude's built-in
/// file tools and to shell reads Claude Code can parse (`cat`, `sed`, `>`),
/// but never to an opaque shell read or a subprocess.
public struct PermissionRules: Sendable, Equatable, Codable {
    public var readDeny: [PathPattern]
    /// `permissions.blockReadsOutsideWorkingDirectories`: file tools refuse any
    /// read outside the working directory, in every mode.
    public var blockReadsOutsideWorkingDirectory: Bool

    public init(readDeny: [PathPattern] = [], blockReadsOutsideWorkingDirectory: Bool = false) {
        self.readDeny = readDeny
        self.blockReadsOutsideWorkingDirectory = blockReadsOutsideWorkingDirectory
    }

    var denySet: ReadRuleSet { ReadRuleSet(allow: [], deny: readDeny) }
}

/// The OS sandbox layer. Applies to shell commands and their child processes
/// only — the built-in file tools run outside it. Filesystem reads are decided
/// by `denyRead`/`allowRead` with "most specific wins"; the default read scope
/// is the whole machine, so an empty rule set blocks nothing.
public struct Sandbox: Sendable, Equatable, Codable {
    public var enabled: Bool
    public var filesystem: ReadRuleSet
    /// Credential files denied to sandboxed commands (folds into the filesystem
    /// deny set at the same precedence as an exact-path `denyRead`).
    public var credentialFiles: [PathPattern]
    /// Hosts sandboxed commands may reach. Empty means none are pre-allowed.
    public var allowedDomains: [String]
    /// Environment variables stripped from sandboxed subprocesses.
    public var credentialEnvVars: [String]
    /// `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`: remove credential-shaped variables
    /// from every subprocess. Leaves `GITHUB_TOKEN`/`GH_TOKEN` in place.
    public var subprocessEnvScrub: Bool
    /// `allowUnsandboxedCommands`. When true, a blocked command can retry
    /// outside the sandbox — an open escape hatch. Strict mode sets it false.
    public var allowUnsandboxedRetry: Bool

    public init(enabled: Bool = false,
                filesystem: ReadRuleSet = ReadRuleSet(),
                credentialFiles: [PathPattern] = [],
                allowedDomains: [String] = [],
                credentialEnvVars: [String] = [],
                subprocessEnvScrub: Bool = false,
                allowUnsandboxedRetry: Bool = true) {
        self.enabled = enabled
        self.filesystem = filesystem
        self.credentialFiles = credentialFiles
        self.allowedDomains = allowedDomains
        self.credentialEnvVars = credentialEnvVars
        self.subprocessEnvScrub = subprocessEnvScrub
        self.allowUnsandboxedRetry = allowUnsandboxedRetry
    }

    /// The effective filesystem rules: declared rules plus credential files as
    /// exact-path denies.
    var effectiveFilesystem: ReadRuleSet {
        ReadRuleSet(allow: filesystem.allow, deny: filesystem.deny + credentialFiles)
    }

    func allowsHost(_ host: String) -> Bool {
        for d in allowedDomains {
            if d == host { return true }
            if d.hasPrefix("*.") {
                let suffix = String(d.dropFirst(1)) // ".example.com"
                if host.hasSuffix(suffix) { return true }
            }
        }
        return false
    }

    /// Variable names the scrub always leaves in place (so `gh` keeps working),
    /// per the documented exceptions.
    static let scrubExceptions: Set<String> = [
        "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"
    ]

    func scrubRemoves(_ name: String) -> Bool {
        guard subprocessEnvScrub else { return false }
        if Sandbox.scrubExceptions.contains(name) { return false }
        let n = name.uppercased()
        // The scrub recognizes a credential by its name shape.
        return n.contains("KEY") || n.contains("SECRET") || n.contains("TOKEN")
            || n.contains("PASSWORD") || n.contains("CREDENTIAL")
    }
}

/// Whether the terminal or IDE the agent runs inside holds Full Disk Access.
/// The agent process never requests FDA; it inherits whatever its parent holds.
/// FDA governs only the TCC-protected set (Messages/Mail/Safari/TCC.db); it has
/// no bearing on `~/.ssh`, `~/.aws` or a project `.env`.
public struct HostAccess: Sendable, Equatable, Codable {
    public var terminalHasFullDiskAccess: Bool
    public init(terminalHasFullDiskAccess: Bool) {
        self.terminalHasFullDiskAccess = terminalHasFullDiskAccess
    }
}

/// A complete agent-access posture: all three layers plus the host state.
public struct AgentPolicy: Sendable, Equatable, Codable {
    public var permissions: PermissionRules
    public var sandbox: Sandbox
    public var host: HostAccess
    public var name: String

    public init(name: String, permissions: PermissionRules, sandbox: Sandbox, host: HostAccess) {
        self.name = name
        self.permissions = permissions
        self.sandbox = sandbox
        self.host = host
    }
}
