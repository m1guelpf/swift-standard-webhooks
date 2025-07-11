import Crypto
import Foundation

let SIGNATURE_VERSION = "v1"
let TOLERANCE_IN_SECONDS = TimeInterval(5 * 60)

public let SECRET_PREFIX = "whsec_"

public struct Webhook {
	public enum Error: Swift.Error, Equatable, Hashable, Sendable {
		case invalidPayload
		case timestampTooOld
		case futureTimestamp
		case invalidSignature
		case missingHeader(String)
		case invalidHeader(String)
	}

	private let key: SymmetricKey

	public init?(secret: String) {
		guard let secret = Data(base64Encoded: secret.dropPrefix(SECRET_PREFIX)) else { return nil }

		key = SymmetricKey(data: secret)
	}

	public init(secretBytes secret: Data) {
		key = SymmetricKey(data: secret)
	}

	public func verify(payload: String, headers: Headers, now: TimeInterval = Date().timeIntervalSince1970) throws(Error) {
		guard let msgId = headers.webhookIdHeader else { throw .missingHeader(HEADER_WEBHOOK_ID) }
		guard let msgSignature = headers.webhookSignatureHeader else { throw .missingHeader(HEADER_WEBHOOK_SIGNATURE) }
		guard let msgTimestampStr = headers.webhookTimestampHeader else { throw .missingHeader(HEADER_WEBHOOK_TIMESTAMP) }

		guard let msgTimestamp = TimeInterval(msgTimestampStr) else { throw Error.invalidHeader(HEADER_WEBHOOK_TIMESTAMP) }

		if now - msgTimestamp > TOLERANCE_IN_SECONDS { throw .timestampTooOld }
		else if msgTimestamp > now + TOLERANCE_IN_SECONDS { throw .futureTimestamp }

		let versionedSignature = sign(id: msgId, payload: payload, timestamp: msgTimestamp)
		guard let expectedSignature = versionedSignature.split(separator: ",").last else { throw .invalidSignature }

		let isValid = msgSignature.split(separator: " ")
			.compactMap { signature -> (String, String)? in
				let components = signature.split(separator: ",", maxSplits: 1)
				guard components.count == 2 else { return nil }

				return (String(components[0]), String(components[1]))
			}
			.filter { $0.0 == SIGNATURE_VERSION }
			.contains { _, signature in
				guard signature.count == expectedSignature.count else { return false }

				let result = zip(signature.utf8, expectedSignature.utf8).reduce(0) { accomulator, charPair in
					let (a, b) = charPair

					return accomulator | (Int(a) ^ Int(b))
				}

				return result == 0
			}

		guard isValid else { throw .invalidSignature }
	}

	public func verify(payload: Data, headers: Headers, now: TimeInterval = Date().timeIntervalSince1970) throws(Error) {
		guard let payload = String(data: payload, encoding: .utf8) else { throw .invalidPayload }

		try verify(payload: payload, headers: headers, now: now)
	}

	public func sign(id: String, payload: String, timestamp: TimeInterval = Date().timeIntervalSince1970) -> String {
		let toSign = "\(id).\(Int(timestamp)).\(payload)"
		let signed = HMAC<SHA256>.authenticationCode(for: Data(toSign.utf8), using: key)

		let encoded = Data(signed).base64EncodedString()

		return "\(SIGNATURE_VERSION),\(encoded)"
	}

	public func sign(id: String, payload: Data, timestamp: TimeInterval = Date().timeIntervalSince1970) throws(Error) -> String {
		guard let payload = String(data: payload, encoding: .utf8) else { throw .invalidPayload }

		return sign(id: id, payload: payload, timestamp: timestamp)
	}
}
