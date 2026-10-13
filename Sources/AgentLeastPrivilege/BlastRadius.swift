// BlastRadius.swift
//
// The output a lead actually cares about: given a policy and a set of things a
// prompt-injected agent would try, which ones still get through, and which
// layer (if any) stopped each. "Blast radius" = the attempts that stay reachable.

import Foundation

public struct EvaluatedAttempt: Sendable, Identifiable, Equatable {
    public let attempt: AccessAttempt
    public let decision: Decision
    public var id: String { attempt.id }
}

public struct BlastRadius: Sendable, Equatable {
    public let policyName: String
    public let evaluated: [EvaluatedAttempt]

    public var reachable: [EvaluatedAttempt] { evaluated.filter { $0.decision.reachable } }
    public var blocked: [EvaluatedAttempt] { evaluated.filter { !$0.decision.reachable } }
    public var reachableCount: Int { reachable.count }
    public var total: Int { evaluated.count }

    /// How many blocked attempts each layer accounts for.
    public func blockedBy(_ layer: DecidingLayer) -> Int {
        blocked.filter { $0.decision.layer == layer }.count
    }

    /// The distinct resources an injected agent still reaches under this policy.
    public var reachableResources: [Resource] {
        var seen: [Resource] = []
        for e in reachable where !seen.contains(e.attempt.resource) {
            seen.append(e.attempt.resource)
        }
        return seen
    }
}

public enum BlastRadiusEvaluator {
    public static func run(_ attempts: [AccessAttempt], under policy: AgentPolicy) -> BlastRadius {
        let gate = LeastPrivilegeGate()
        let evaluated = attempts.map { EvaluatedAttempt(attempt: $0, decision: gate.evaluate($0, under: policy)) }
        return BlastRadius(policyName: policy.name, evaluated: evaluated)
    }
}
