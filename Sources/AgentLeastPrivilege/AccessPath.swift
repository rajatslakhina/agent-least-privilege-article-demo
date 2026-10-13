// AccessPath.swift
//
// The vocabulary: a coding agent can touch a resource through several
// different *readers*, and which policy layer governs a read depends
// entirely on which reader made it. That asymmetry is the whole point of
// this library, so it is modelled explicitly rather than collapsed into
// one "can read" predicate.

import Foundation

/// A fixed, fake filesystem layout so paths are deterministic in tests and
/// on every machine. `home` stands in for the engineer's home directory and
/// `workingDirectory` for the repo the agent was pointed at.
public enum Layout {
    public static let home = "/Users/dev"
    public static let workingDirectory = "/Users/dev/app"
}

/// How the agent reaches a resource. Each case is a distinct enforcement
/// surface, documented inline with the Claude Code behaviour it mirrors.
public enum Reader: String, Sendable, CaseIterable, Codable {
    /// Claude's built-in Read/Edit/Write/Grep/Glob tools. Governed by
    /// permission Read/Edit deny rules and by
    /// `permissions.blockReadsOutsideWorkingDirectories`. The OS sandbox
    /// does **not** cover these: "A `denyRead` entry doesn't stop the Read tool."
    case builtInFileTool

    /// A shell command Claude Code recognizes as reading a named file:
    /// `cat`, `head`, `tail`, `sed`, `tee`, and `>`/`<` redirections.
    /// Governed by permission Read deny rules AND by the sandbox.
    case recognizedShellRead

    /// A shell read the command text does not name: `grep -r` from the
    /// directory, or a `python`/`node` script that opens the file itself.
    /// Permission Read deny rules do NOT see it. Only the sandbox can stop it.
    case opaqueShellRead

    /// A subprocess reading a secret out of its environment. Governed by
    /// `sandbox.credentials.envVars` deny and `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`.
    case subprocessEnv

    /// A shell command opening a network connection (the exfiltration leg).
    /// Governed by the sandbox network allowlist.
    case shellNetwork

    public var label: String {
        switch self {
        case .builtInFileTool: return "Read tool"
        case .recognizedShellRead: return "named shell read"
        case .opaqueShellRead: return "opaque shell read"
        case .subprocessEnv: return "subprocess env"
        case .shellNetwork: return "shell network"
        }
    }
}

/// What the agent is trying to reach.
public enum Resource: Sendable, Equatable, Codable {
    /// A file in the home directory that the OS does not specially protect
    /// (`~/.ssh/id_rsa`, `~/.aws/credentials`, a project `.env`, shell history).
    case file(String)
    /// A file TCC protects: Messages/Mail/Safari data, the TCC database.
    /// Unreachable by any process unless the agent's terminal holds Full Disk Access.
    case osProtectedFile(String)
    /// A secret held in an environment variable.
    case envVar(String)
    /// An outbound host (the exfiltration destination).
    case host(String)

    public var display: String {
        switch self {
        case .file(let p), .osProtectedFile(let p): return p
        case .envVar(let v): return "$\(v)"
        case .host(let h): return h
        }
    }
}

/// One concrete thing a prompt-injected agent might try, e.g.
/// "a python script reads ~/.ssh/id_rsa".
public struct AccessAttempt: Sendable, Identifiable, Equatable, Codable {
    public let id: String
    public let reader: Reader
    public let resource: Resource
    /// Human-readable technique, e.g. `python3 -c "open('~/.ssh/id_rsa')"`.
    public let technique: String

    public init(id: String, reader: Reader, resource: Resource, technique: String) {
        self.id = id
        self.reader = reader
        self.resource = resource
        self.technique = technique
    }
}
