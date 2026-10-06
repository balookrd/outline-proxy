// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OutlineProxy",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "OutlineProxy", targets: ["OutlineProxy"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "OutlineProxy",
            path: "Sources/OutlineProxy"
        )
    ]
)
