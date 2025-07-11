// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "StandardWebhooks",
    platforms: [
        .iOS(.v17),
        .tvOS(.v17),
        .macOS(.v14),
        .watchOS(.v10),
        .visionOS(.v1),
        .macCatalyst(.v17),
    ],
    products: [
        .library(name: "StandardWebhooks", type: .static, targets: ["StandardWebhooks"]),
    ],
    traits: [
        .default(enabledTraits: []),
        .trait(name: "NIO", description: "Enables NIO support for webhooks, allowing verification using NIOHTTP1 headers."),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0"),
    ],
    targets: [
        .target(
            name: "StandardWebhooks",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOHTTP1", package: "swift-nio", condition: .when(traits: ["NIO"])),
            ],
            path: "./src"
        ),
        .testTarget(name: "StandardWebhooksTests", dependencies: ["StandardWebhooks"], path: "./tests"),
    ]
)
