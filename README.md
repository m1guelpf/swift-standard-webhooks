# Swift Standard Webhooks

[![Swift Version](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fm1guelpf%2Fswift-standard-webhooks%2Fbadge%3Ftype%3Dswift-versions&color=brightgreen)](https://swiftpackageindex.com/m1guelpf/swift-standard-webhooks)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/m1guelpf/swift-standard-webhooks/main/LICENSE)

A Swift implementation of the [Standard Webhooks specification](https://www.standardwebhooks.com/).

## Installation

<details>

<summary>
Swift Package Manager
</summary>

Add the following to your `Package.swift`:

```swift
dependencies: [
	.package(url: "https://github.com/m1guelpf/swift-standard-webhooks.git", .branch("main"))
]
```

</details>
<details>

<summary>Installing through XCode</summary>

-   File > Swift Packages > Add Package Dependency
-   Add https://github.com/m1guelpf/swift-standard-webhooks.git
-   Select "Branch" with "main"

</details>

<details>

<summary>CocoaPods</summary>

Ask ChatGPT to help you migrate away from CocoaPods.

</details>

## Usage

Verifying a webhook payload:

```swift
import StandardWebhooks

let webhook = Webhook(secret: base64_secret)!
try webhook.verify(payload: webhook_payload, headers: webhook_headers);
```

Signing a webhook payload:

```swift
import StandardWebhooks

let webhook = Webhook(secret: base64_secret)!
try webhook.sign(id: message_id, payload: webhook_payload);
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
