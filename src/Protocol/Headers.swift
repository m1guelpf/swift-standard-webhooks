import Foundation

public let HEADER_WEBHOOK_ID = "webhook-id"
public let HEADER_WEBHOOK_SIGNATURE = "webhook-signature"
public let HEADER_WEBHOOK_TIMESTAMP = "webhook-timestamp"

public protocol Headers {
	var webhookIdHeader: String? { get }
	var webhookSignatureHeader: String? { get }
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
