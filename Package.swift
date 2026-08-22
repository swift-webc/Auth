// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "Auth",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "Authorization",
            targets: [
                "Authorization",
            ]
        ),
        .library(
            name: "AuthorizationCapability",
            targets: [
                "AuthorizationCapability",
            ]
        ),
        .library(
            name: "Authentication",
            targets: [
                "Authentication",
            ]
        ),
        .library(
            name: "AuthenticationPassword",
            targets: [
                "AuthenticationPassword",
            ]
        ),
        .library(
            name: "AuthenticationToken",
            targets: [
                "AuthenticationToken",
            ]
        ),
        .library(
            name: "AuthenticationServer",
            targets: [
                "AuthenticationServer",
            ]
        ),
        .executable(
            name: "authtest",
            targets: [
                "AuthenticationTestFlows",
            ]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/jedisct1/swift-sodium.git",
            exact: "0.11.0"
        ),
        .package(
            url: "https://github.com/vapor/jwt-kit.git",
            exact: "5.6.0"
        ),
        .package(
            url: "https://github.com/leviouwendijk/HTTP.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/leviouwendijk/Server.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/leviouwendijk/Primitives.git",
            branch: "master"
        ),
        .package(
            url: "https://github.com/leviouwendijk/TestFlows.git",
            branch: "master"
        ),
    ],
    targets: [
        .target(
            name: "Authorization",
            dependencies: [
                .product(
                    name: "Primitives",
                    package: "Primitives"
                ),
            ]
        ),
        .target(
            name: "AuthorizationCapability",
            dependencies: [
                .product(
                    name: "Sodium",
                    package: "swift-sodium"
                ),
            ]
        ),
        .target(
            name: "Authentication",
            dependencies: [
                "Authorization",
                .product(
                    name: "Primitives",
                    package: "Primitives"
                ),
            ]
        ),
        .target(
            name: "AuthenticationPassword",
            dependencies: [
                "Authentication",
                .product(
                    name: "Sodium",
                    package: "swift-sodium"
                ),
            ]
        ),
        .target(
            name: "AuthenticationToken",
            dependencies: [
                "Authorization",
                "Authentication",
                .product(
                    name: "JWTKit",
                    package: "jwt-kit"
                ),
                .product(
                    name: "Primitives",
                    package: "Primitives"
                ),
            ]
        ),
        .target(
            name: "AuthenticationServer",
            dependencies: [
                "Authorization",
                "Authentication",
                "AuthenticationToken",
                .product(
                    name: "HTTP",
                    package: "HTTP"
                ),
                .product(
                    name: "Server",
                    package: "Server"
                ),
            ]
        ),
        .executableTarget(
            name: "AuthenticationTestFlows",
            dependencies: [
                "Authorization",
                "AuthorizationCapability",
                "Authentication",
                "AuthenticationPassword",
                "AuthenticationToken",
                "AuthenticationServer",
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
