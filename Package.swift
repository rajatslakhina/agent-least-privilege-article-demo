// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AgentLeastPrivilege",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "AgentLeastPrivilege", targets: ["AgentLeastPrivilege"])
    ],
    targets: [
        .target(name: "AgentLeastPrivilege"),
        .testTarget(name: "AgentLeastPrivilegeTests", dependencies: ["AgentLeastPrivilege"])
    ]
)
