// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "AuthTests",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(
            name: "authtest",
            targets: [
                "AuthenticationTestFlows",
            ]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-webc/HTTP.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/swift-webc/Server.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/leviouwendijk/Primitives.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/swift-tooling/TestFlows.git",
            branch: "master"
        ),
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "AuthenticationTestFlows",
            dependencies: [
                .product(name: "Authorization", package: "Auth"),
                .product(name: "AuthorizationCapability", package: "Auth"),
                .product(name: "Authentication", package: "Auth"),
                .product(name: "AuthenticationPassword", package: "Auth"),
                .product(name: "AuthenticationToken", package: "Auth"),
                .product(name: "AuthenticationServer", package: "Auth"),
                .product(
                    name: "HTTP",
                    package: "HTTP"
                ),
                .product(
                    name: "Server",
                    package: "Server"
                ),
                .product(
                    name: "Primitives",
                    package: "Primitives"
                ),
                .product(
                    name: "TestFlows",
                    package: "TestFlows"
                ),
            ]
        ),
    ],
    swiftLanguageModes: [
        .v6,
    ]
)
