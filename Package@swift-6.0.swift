// swift-tools-version: 6.0

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
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0"),
    ],
    targets: [
        .target(
            name: "StandardWebhooks",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "./src"
        ),
        .testTarget(name: "StandardWebhooksTests", dependencies: ["StandardWebhooks"], path: "./tests"),
    ]
)
