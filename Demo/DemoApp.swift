import SwiftUI
import AgentLeastPrivilege

@main
struct DemoApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

/// CI opens a specific screen with `-tab presets|attempts|crux` and
/// `-preset out|deny|sandbox|lead`.
private enum LaunchOptions {
    static var tab: String { UserDefaults.standard.string(forKey: "tab") ?? "presets" }
    static var preset: String { UserDefaults.standard.string(forKey: "preset") ?? "deny" }
}

private func policy(for key: String) -> AgentPolicy {
    switch key {
    case "out": return SampleScenario.outOfTheBox
    case "sandbox": return SampleScenario.sandboxOnly
    case "lead": return SampleScenario.leadPolicy
    default: return SampleScenario.denyRuleOnly
    }
}

struct RootView: View {
    @State private var tab = LaunchOptions.tab

    var body: some View {
        TabView(selection: $tab) {
            PresetsView()
                .tabItem { Label("Policies", systemImage: "lock.shield") }
                .tag("presets")
            AttemptsView(presetKey: LaunchOptions.preset)
                .tabItem { Label("Blast radius", systemImage: "scope") }
                .tag("attempts")
            CruxView()
                .tabItem { Label("The crux", systemImage: "exclamationmark.triangle") }
                .tag("crux")
        }
    }
}

// MARK: Policies

struct PresetsView: View {
    private var rows: [BlastRadius] { SampleScenario.presets.map { SampleScenario.blastRadius(for: $0) } }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(rows, id: \.policyName) { br in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(br.policyName).font(.headline)
                                Spacer()
                                Text("\(br.reachableCount) of \(br.total) reachable")
                                    .font(.subheadline.monospacedDigit())
                                    .foregroundStyle(br.reachableCount == 0 ? .green : .red)
                            }
                            ReachBar(reachable: br.reachableCount, total: br.total)
                            Text(blockSummary(br)).font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                } header: {
                    Text("What a prompt-injected agent still reaches")
                } footer: {
                    Text("12 constructed access attempts, evaluated by LeastPrivilegeGate. A worked example, not a survey of real attacks.")
                }
            }
            .navigationTitle("Least privilege")
        }
    }

    private func blockSummary(_ br: BlastRadius) -> String {
        if br.reachableCount == br.total { return "nothing configured" }
        var parts: [String] = []
        if br.blockedBy(.permissionRules) > 0 { parts.append("\(br.blockedBy(.permissionRules)) by permission rules") }
        if br.blockedBy(.sandbox) > 0 { parts.append("\(br.blockedBy(.sandbox)) by sandbox") }
        if br.blockedBy(.operatingSystem) > 0 { parts.append("\(br.blockedBy(.operatingSystem)) by the OS (no FDA)") }
        return "blocked: " + parts.joined(separator: ", ")
    }
}

struct ReachBar: View {
    let reachable: Int
    let total: Int
    var body: some View {
        GeometryReader { geo in
            HStack(spacing: 2) {
                ForEach(0..<max(total, 1), id: \.self) { i in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(i < reachable ? Color.red : Color.green)
                }
            }
        }
        .frame(height: 10)
    }
}

// MARK: Blast radius for one policy

struct AttemptsView: View {
    let presetKey: String
    @State private var key: String

    init(presetKey: String) {
        self.presetKey = presetKey
        _key = State(initialValue: presetKey)
    }

    private var br: BlastRadius { SampleScenario.blastRadius(for: policy(for: key)) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("Policy", selection: $key) {
                        Text("Out of the box").tag("out")
                        Text("Deny rule only").tag("deny")
                        Text("Sandbox only").tag("sandbox")
                        Text("Lead policy").tag("lead")
                    }
                    .pickerStyle(.menu)
                    LabeledContent("Reachable", value: "\(br.reachableCount) of \(br.total)")
                }
                Section("Every attempt") {
                    ForEach(br.evaluated) { e in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: e.decision.reachable ? "xmark.octagon.fill" : "checkmark.shield.fill")
                                .foregroundStyle(e.decision.reachable ? .red : .green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(e.attempt.technique).font(.subheadline)
                                Text(e.decision.reachable
                                     ? "REACHABLE — \(e.decision.reason)"
                                     : "blocked by \(e.decision.layer.rawValue) — \(e.decision.reason)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .navigationTitle(policy(for: key).name)
        }
    }
}

// MARK: The crux

struct CruxView: View {
    private let attemptID = "A06"
    private func reachable(_ p: AgentPolicy) -> Bool {
        SampleScenario.blastRadius(for: p).reachable.contains { $0.attempt.id == attemptID }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("grep -r SECRET .").font(.body.monospaced())
                    Text("An opaque shell read of the repo's own .env. It never names the file, so a Read deny rule can't see it; and `allowRead .` re-opened the repo, so a sandbox that only denies ~/ lets it through.")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: { Text("The one attempt that needs both layers") }

                Section("Reachable under…") {
                    row("Deny rule only", reachable(SampleScenario.denyRuleOnly))
                    row("Sandbox only", reachable(SampleScenario.sandboxOnly))
                    row("Lead policy (both + FDA off)", reachable(SampleScenario.leadPolicy))
                }
            }
            .navigationTitle("The crux")
        }
    }

    private func row(_ name: String, _ reach: Bool) -> some View {
        HStack {
            Text(name)
            Spacer()
            Text(reach ? "reachable" : "blocked")
                .font(.subheadline.bold())
                .foregroundStyle(reach ? .red : .green)
        }
    }
}
