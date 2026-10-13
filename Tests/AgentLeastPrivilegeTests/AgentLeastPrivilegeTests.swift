import XCTest
@testable import AgentLeastPrivilege

final class PathPatternTests: XCTestCase {

    // The three overlap cases from the Claude Code sandbox docs must resolve
    // exactly as documented: most specific wins, deny breaks ties.
    func testNarrowerAllowReopensInsideBroaderDeny() {
        let rs = ReadRuleSet(allow: [PathPattern("~/app")], deny: [PathPattern("~/")])
        XCTAssertEqual(rs.decide("/Users/dev/app/file.swift"), .allowed)
        XCTAssertEqual(rs.decide("/Users/dev/.ssh/id_rsa"), .denied)
    }

    func testExactDenyHoldsInsideBroaderAllow() {
        let rs = ReadRuleSet(allow: [PathPattern("~/")], deny: [PathPattern("~/.env")])
        XCTAssertEqual(rs.decide("/Users/dev/.env"), .denied)
        XCTAssertEqual(rs.decide("/Users/dev/notes.md"), .allowed)
    }

    func testWildcardDenyHoldsInsideBroaderAllow() {
        let rs = ReadRuleSet(allow: [PathPattern("~/")], deny: [PathPattern("**/.env")])
        XCTAssertEqual(rs.decide("/Users/dev/app/.env"), .denied)
        XCTAssertEqual(rs.decide("/Users/dev/app/main.swift"), .allowed)
    }

    func testBasenameMatchesAtAnyDepthOnly() {
        let p = PathPattern("**/.env")
        XCTAssertTrue(p.matches("/Users/dev/app/.env"))
        XCTAssertTrue(p.matches("/Users/dev/app/sub/.env"))
        XCTAssertFalse(p.matches("/Users/dev/app/.environment"))
    }

    func testNoRuleMeansNoOpinion() {
        XCTAssertEqual(ReadRuleSet().decide("/Users/dev/.ssh/id_rsa"), .noOpinion)
    }
}

final class GateReaderAsymmetryTests: XCTestCase {
    let gate = LeastPrivilegeGate()

    // The sandbox does not cover the built-in Read tool.
    func testSandboxDoesNotCoverTheReadTool() {
        let policy = SampleScenario.sandboxOnly
        let readTool = AccessAttempt(id: "x", reader: .builtInFileTool,
                                     resource: .file("\(Layout.home)/.ssh/id_rsa"),
                                     technique: "Read tool")
        XCTAssertTrue(gate.evaluate(readTool, under: policy).reachable)
    }

    // A Read deny rule does not cover an opaque shell read.
    func testDenyRuleDoesNotCoverOpaqueShellRead() {
        let policy = SampleScenario.denyRuleOnly
        let opaque = AccessAttempt(id: "x", reader: .opaqueShellRead,
                                   resource: .file("\(Layout.home)/.ssh/id_rsa"),
                                   technique: "python open()")
        XCTAssertTrue(gate.evaluate(opaque, under: policy).reachable)
        // ...but it does cover the Read tool and a named `cat`.
        let named = AccessAttempt(id: "y", reader: .recognizedShellRead,
                                  resource: .file("\(Layout.home)/.ssh/id_rsa"),
                                  technique: "cat")
        XCTAssertFalse(gate.evaluate(named, under: policy).reachable)
    }

    // allowRead "." re-opens the repo, so a project .env is still readable by
    // the shell under a sandbox that only denies ~/.
    func testAllowReadRepoReopensProjectEnvForShell() {
        let policy = SampleScenario.sandboxOnly
        let env = AccessAttempt(id: "x", reader: .opaqueShellRead,
                                resource: .file("\(Layout.workingDirectory)/.env"),
                                technique: "grep -r")
        XCTAssertTrue(gate.evaluate(env, under: policy).reachable)
    }

    // Full Disk Access on the terminal is what gates TCC-protected data.
    func testFullDiskAccessGatesProtectedData() {
        let chatDB = AccessAttempt(id: "x", reader: .opaqueShellRead,
                                   resource: .osProtectedFile("\(Layout.home)/Library/Messages/chat.db"),
                                   technique: "sqlite3")
        let fdaOff = AgentPolicy(name: "fda off", permissions: PermissionRules(),
                                 sandbox: Sandbox(enabled: false),
                                 host: HostAccess(terminalHasFullDiskAccess: false))
        XCTAssertFalse(gate.evaluate(chatDB, under: fdaOff).reachable)
        XCTAssertEqual(gate.evaluate(chatDB, under: fdaOff).layer, .operatingSystem)

        let fdaOn = AgentPolicy(name: "fda on", permissions: PermissionRules(),
                                sandbox: Sandbox(enabled: false),
                                host: HostAccess(terminalHasFullDiskAccess: true))
        XCTAssertTrue(gate.evaluate(chatDB, under: fdaOn).reachable)
    }

    func testEnvScrubLeavesGithubTokenButRemovesSecrets() {
        var sandbox = Sandbox(enabled: true, subprocessEnvScrub: true)
        sandbox.allowUnsandboxedRetry = false
        let policy = AgentPolicy(name: "scrub", permissions: PermissionRules(),
                                 sandbox: sandbox, host: HostAccess(terminalHasFullDiskAccess: false))
        let secret = AccessAttempt(id: "s", reader: .subprocessEnv,
                                   resource: .envVar("AWS_SECRET_ACCESS_KEY"), technique: "env")
        let gh = AccessAttempt(id: "g", reader: .subprocessEnv,
                               resource: .envVar("GITHUB_TOKEN"), technique: "env")
        XCTAssertFalse(gate.evaluate(secret, under: policy).reachable)
        XCTAssertTrue(gate.evaluate(gh, under: policy).reachable)
    }

    func testStrictAllowlistClosesTheRetryHatch() {
        let open = AccessAttempt(id: "n", reader: .shellNetwork,
                                 resource: .host("evil.example.com"), technique: "curl")
        // retry hatch open -> reachable even though evil isn't allowlisted
        var s1 = Sandbox(enabled: true, allowedDomains: ["github.com"])
        s1.allowUnsandboxedRetry = true
        let open1 = AgentPolicy(name: "hatch", permissions: PermissionRules(), sandbox: s1,
                                host: HostAccess(terminalHasFullDiskAccess: false))
        XCTAssertTrue(gate.evaluate(open, under: open1).reachable)
        // strict -> blocked
        var s2 = s1; s2.allowUnsandboxedRetry = false
        let strict = AgentPolicy(name: "strict", permissions: PermissionRules(), sandbox: s2,
                                 host: HostAccess(terminalHasFullDiskAccess: false))
        XCTAssertFalse(gate.evaluate(open, under: strict).reachable)
    }
}

final class BlastRadiusTests: XCTestCase {

    func testOutOfTheBoxReachesEverything() {
        let br = SampleScenario.blastRadius(for: SampleScenario.outOfTheBox)
        XCTAssertEqual(br.total, 12)
        XCTAssertEqual(br.reachableCount, 12)
    }

    func testDenyRuleOnlyLeavesSixReachable() {
        let br = SampleScenario.blastRadius(for: SampleScenario.denyRuleOnly)
        XCTAssertEqual(br.reachableCount, 6)
        // every block it does make comes from the permission layer
        XCTAssertEqual(br.blockedBy(.permissionRules), 6)
        XCTAssertEqual(br.blockedBy(.sandbox), 0)
    }

    func testSandboxOnlyLeavesFiveReachable() {
        let br = SampleScenario.blastRadius(for: SampleScenario.sandboxOnly)
        XCTAssertEqual(br.reachableCount, 5)
        XCTAssertEqual(br.blockedBy(.sandbox), 7)
    }

    // The crux: `grep -r` reading the repo's own .env (A06) is the one attempt
    // that slips past BOTH single-layer policies and is caught only by running both.
    func testRepoEnvOpaqueReadSlipsPastBothSingleLayers() {
        let denyBR = SampleScenario.blastRadius(for: SampleScenario.denyRuleOnly)
        let sandboxBR = SampleScenario.blastRadius(for: SampleScenario.sandboxOnly)
        let leadBR = SampleScenario.blastRadius(for: SampleScenario.leadPolicy)
        func reachable(_ id: String, _ br: BlastRadius) -> Bool {
            br.reachable.contains { $0.attempt.id == id }
        }
        XCTAssertTrue(reachable("A06", denyBR))
        XCTAssertTrue(reachable("A06", sandboxBR))
        XCTAssertFalse(reachable("A06", leadBR))
    }

    func testLeadPolicyReachesZero() {
        let br = SampleScenario.blastRadius(for: SampleScenario.leadPolicy)
        XCTAssertEqual(br.reachableCount, 0)
        XCTAssertEqual(br.blockedBy(.permissionRules), 4)
        XCTAssertEqual(br.blockedBy(.sandbox), 7)
        XCTAssertEqual(br.blockedBy(.operatingSystem), 1)
    }

    func testSingleLayerReachableSetsDiffer() {
        let deny = Set(SampleScenario.blastRadius(for: SampleScenario.denyRuleOnly).reachable.map { $0.attempt.id })
        let sandbox = Set(SampleScenario.blastRadius(for: SampleScenario.sandboxOnly).reachable.map { $0.attempt.id })
        // Different holes: their only shared survivor is the repo .env opaque read.
        XCTAssertNotEqual(deny, sandbox)
        XCTAssertEqual(deny.intersection(sandbox), ["A06"])
    }

    // Edge case: the lead policy's `**/.env` deny catches a .env nested deep in
    // the repo, not just one at the repo root.
    func testLeadPolicyBlocksNestedRepoEnv() {
        let nested = AccessAttempt(id: "n", reader: .opaqueShellRead,
                                   resource: .file("\(Layout.workingDirectory)/Secrets/prod/.env"),
                                   technique: "python open(nested .env)")
        XCTAssertFalse(LeastPrivilegeGate().evaluate(nested, under: SampleScenario.leadPolicy).reachable)
    }

    // Edge case: blockReadsOutsideWorkingDirectories must NOT block a file-tool
    // read of a normal source file inside the repo.
    func testLeadPolicyStillLetsAgentReadRepoSource() {
        let src = AccessAttempt(id: "s", reader: .builtInFileTool,
                                resource: .file("\(Layout.workingDirectory)/Sources/App/Main.swift"),
                                technique: "Read tool opens a source file")
        XCTAssertTrue(LeastPrivilegeGate().evaluate(src, under: SampleScenario.leadPolicy).reachable)
    }

    // Prints the real table the article quotes. Never fails; just records numbers.
    func testPrintTable() {
        print("\n  policy              reachable/total   perm  sandbox  OS")
        for p in SampleScenario.presets {
            let br = SampleScenario.blastRadius(for: p)
            let name = p.name.padding(toLength: 18, withPad: " ", startingAt: 0)
            print(String(format: "  %@      %2d/%2d          %2d     %2d     %2d",
                         name, br.reachableCount, br.total,
                         br.blockedBy(.permissionRules), br.blockedBy(.sandbox),
                         br.blockedBy(.operatingSystem)))
        }
        print("")
    }
}
