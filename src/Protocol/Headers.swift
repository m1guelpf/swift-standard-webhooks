import Foundation

/// The header name for the webhook event ID.
public let HEADER_WEBHOOK_ID = "webhook-id"

/// The header name for the webhook signature.
public let HEADER_WEBHOOK_SIGNATURE = "webhook-signature"

/// The header name for the webhook timestamp.
public let HEADER_WEBHOOK_TIMESTAMP = "webhook-timestamp"

/// A collection of HTTP headers that may contain webhook authentication information.
public protocol Headers {
    /// The value of the header identifying the webhook event (`webhook-id`), if present.
    var webhookIdHeader: String? { get }

    /// The value of the header containing the webhook signature (`webhook-signature`), if present.
    var webhookSignatureHeader: String? { get }

    /// The value of the header indicating when the webhook was generated (`webhook-timestamp`), if present.
    var webhookTimestampHeader: String? { get }
}

extension Dictionary: Headers where Key == String, Value == String {
    public var webhookIdHeader: String? {
        return self[HEADER_WEBHOOK_ID]
    }

    public var webhookSignatureHeader: String? {
        return self[HEADER_WEBHOOK_SIGNATURE]
    }

    public var webhookTimestampHeader: String? {
        return self[HEADER_WEBHOOK_TIMESTAMP]
    }
}

#if NIO
import NIOHTTP1

extension HTTPHeaders: Headers {
    public var webhookIdHeader: String? {
        return self[HEADER_WEBHOOK_ID].first
    }

    public var webhookSignatureHeader: String? {
        return self[HEADER_WEBHOOK_SIGNATURE].first
    }

    public var webhookTimestampHeader: String? {
        return self[HEADER_WEBHOOK_TIMESTAMP].first
    }
}
#endif

#if SwiftHTTPTypes
import HTTPTypes

extension HTTPField.Name {
    static let webhookId = Self(HEADER_WEBHOOK_ID)!
    static let webhookTimestamp = Self(HEADER_WEBHOOK_TIMESTAMP)!
    static let webhookSignature = Self(HEADER_WEBHOOK_SIGNATURE)!
}

extension HTTPFields: Headers {
    public var webhookIdHeader: String? {
        return self[.webhookId]
    }

    public var webhookSignatureHeader: String? {
        return self[.webhookSignature]
    }

    public var webhookTimestampHeader: String? {
        return self[.webhookTimestamp]
    }
}

#endif
