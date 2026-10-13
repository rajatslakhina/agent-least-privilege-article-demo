// Gate.swift
//
// The evaluator. Given one access attempt and a policy, it returns whether an
// injected agent reaches the resource and, if blocked, which layer stopped it.
// The ordering encodes the real precedence: the OS (TCC) decides first for a
// protected file, then the layer that actually covers the reader.

import Foundation

/// Which layer decided the outcome.
public enum DecidingLayer: String, Sendable, Codable {
    case operatingSystem   // TCC / Full Disk Access
    case permissionRules   // Read deny rule or blockReads
    case sandbox           // sandbox filesystem / credentials / network
    case subprocessScrub   // CLAUDE_CODE_SUBPROCESS_ENV_SCRUB
    case none              // nothing stopped it
}

public struct Decision: Sendable, Equatable, Codable {
    public let reachable: Bool
    public let layer: DecidingLayer
    /// A short, quotable reason, e.g. "sandbox denyRead ~/ (most specific)".
    public let reason: String
}

public struct LeastPrivilegeGate: Sendable {
    public init() {}

    private func isOutsideWorkingDirectory(_ path: String) -> Bool {
        !(path == Layout.workingDirectory || path.hasPrefix(Layout.workingDirectory + "/"))
    }

    /// Does the OS block this resource outright? Only TCC-protected files, and
    /// only when the terminal lacks Full Disk Access.
    private func osBlocks(_ resource: Resource, _ policy: AgentPolicy) -> Bool {
        if case .osProtectedFile = resource {
            return !policy.host.terminalHasFullDiskAccess
        }
        return false
    }

    public func evaluate(_ attempt: AccessAttempt, under policy: AgentPolicy) -> Decision {
        let resource = attempt.resource

        // 1. The OS has the first and final say on TCC-protected files.
        if osBlocks(resource, policy) {
            return Decision(reachable: false, layer: .operatingSystem,
                            reason: "TCC blocks protected data; terminal has no Full Disk Access")
        }

        switch attempt.reader {
        case .builtInFileTool:
            return fileToolDecision(resource, policy)
        case .recognizedShellRead:
            return recognizedShellDecision(resource, policy)
        case .opaqueShellRead:
            return opaqueShellDecision(resource, policy)
        case .subprocessEnv:
            return envDecision(resource, policy)
        case .shellNetwork:
            return networkDecision(resource, policy)
        }
    }

    // Built-in file tools: permission layer only. The sandbox never covers them.
    private func fileToolDecision(_ resource: Resource, _ policy: AgentPolicy) -> Decision {
        guard case .file(let path) = resource else {
            // osProtectedFile already cleared OS check (FDA on); file tool still
            // needs a permission deny to be stopped.
            if case .osProtectedFile(let path) = resource {
                return permissionOnly(path, policy, readerIsFileTool: true)
            }
            return Decision(reachable: true, layer: .none, reason: "file tool, no file-read rule applies")
        }
        return permissionOnly(path, policy, readerIsFileTool: true)
    }

    private func permissionOnly(_ path: String, _ policy: AgentPolicy, readerIsFileTool: Bool) -> Decision {
        if policy.permissions.denySet.decide(path) == .denied {
            return Decision(reachable: false, layer: .permissionRules,
                            reason: "Read deny rule matches \(path)")
        }
        if readerIsFileTool, policy.permissions.blockReadsOutsideWorkingDirectory,
           isOutsideWorkingDirectory(path) {
            return Decision(reachable: false, layer: .permissionRules,
                            reason: "blockReadsOutsideWorkingDirectories refuses \(path)")
        }
        return Decision(reachable: true, layer: .none,
                        reason: "no permission rule covers \(path); sandbox does not see file tools")
    }

    // Recognized shell reads: permission deny first (Claude Code parses the
    // path), then the sandbox.
    private func recognizedShellDecision(_ resource: Resource, _ policy: AgentPolicy) -> Decision {
        let path = filePath(resource)
        if policy.permissions.denySet.decide(path) == .denied {
            return Decision(reachable: false, layer: .permissionRules,
                            reason: "Read deny rule matches recognized read of \(path)")
        }
        return sandboxFilesystemDecision(path, policy)
    }

    // Opaque shell reads: the permission layer cannot see the path, so only the
    // sandbox can stop it.
    private func opaqueShellDecision(_ resource: Resource, _ policy: AgentPolicy) -> Decision {
        let path = filePath(resource)
        return sandboxFilesystemDecision(path, policy)
    }

    private func sandboxFilesystemDecision(_ path: String, _ policy: AgentPolicy) -> Decision {
        guard policy.sandbox.enabled else {
            return Decision(reachable: true, layer: .none,
                            reason: "sandbox off; shell reads the whole machine")
        }
        if policy.sandbox.effectiveFilesystem.decide(path) == .denied {
            return Decision(reachable: false, layer: .sandbox,
                            reason: "sandbox denyRead/credentials blocks \(path)")
        }
        return Decision(reachable: true, layer: .none,
                        reason: "sandbox read scope still allows \(path)")
    }

    private func envDecision(_ resource: Resource, _ policy: AgentPolicy) -> Decision {
        guard case .envVar(let name) = resource else {
            return Decision(reachable: true, layer: .none, reason: "not an env read")
        }
        if policy.sandbox.enabled, policy.sandbox.credentialEnvVars.contains(name) {
            return Decision(reachable: false, layer: .sandbox,
                            reason: "sandbox credentials unset $\(name)")
        }
        if policy.sandbox.scrubRemoves(name) {
            return Decision(reachable: false, layer: .subprocessScrub,
                            reason: "subprocess env scrub removes $\(name)")
        }
        return Decision(reachable: true, layer: .none, reason: "$\(name) still in subprocess env")
    }

    private func networkDecision(_ resource: Resource, _ policy: AgentPolicy) -> Decision {
        guard case .host(let host) = resource else {
            return Decision(reachable: true, layer: .none, reason: "not a network attempt")
        }
        guard policy.sandbox.enabled else {
            return Decision(reachable: true, layer: .none, reason: "sandbox off; no network containment")
        }
        if policy.sandbox.allowsHost(host) {
            return Decision(reachable: true, layer: .none, reason: "\(host) is on the allowlist")
        }
        if policy.sandbox.allowUnsandboxedRetry {
            return Decision(reachable: true, layer: .none,
                            reason: "blocked, but the unsandboxed-retry hatch is open")
        }
        return Decision(reachable: false, layer: .sandbox,
                        reason: "strict allowlist refuses \(host)")
    }

    private func filePath(_ resource: Resource) -> String {
        switch resource {
        case .file(let p), .osProtectedFile(let p): return p
        case .envVar(let v): return v
        case .host(let h): return h
        }
    }
}
