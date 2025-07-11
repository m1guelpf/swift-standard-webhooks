import Crypto
import Foundation

let SIGNATURE_VERSION = "v1"
let TOLERANCE_IN_SECONDS = TimeInterval(5 * 60) // 5 minutes

/// The prefix for webhook secrets.
public let SECRET_PREFIX = "whsec_"

/// A cryptographically secure utility for signing and verifying webhook payloads using HMAC-SHA256.
///
/// `Webhook` provides methods to generate and validate versioned signatures for payloads, conforming to the Standard Webhooks specification.
///
/// > See [Standard Webhooks](https://standardwebhooks.org) for more details.
public struct Webhook {
	/// Error types thrown by `Webhook` during signature verification and signing operations.
	public enum Error: Swift.Error, Equatable, Hashable, Sendable {
		/// The provided payload could not be decoded as UTF-8.
		case invalidPayload

		/// The payload's timestamp is older than the allowed tolerance window.
		case timestampTooOld

		/// The payload's timestamp is too far in the future, beyond the allowed tolerance window.
		case futureTimestamp

		/// The provided signature does not match the expected value.
		case invalidSignature

		/// A required header is missing in the request.
		case missingHeader(String)

		/// A required header is present but malformed or invalid.
		case invalidHeader(String)

		var localizedDescription: String {
			switch self {
				case .invalidPayload:
					return "The payload could not be decoded as UTF-8."
				case .timestampTooOld:
					return "The timestamp of the payload is too old."
				case .futureTimestamp:
					return "The timestamp of the payload is in the future."
				case .invalidSignature:
					return "The provided signature does not match the expected value."
				case let .missingHeader(header):
					return "Missing required header: \(header)"
				case let .invalidHeader(header):
					return "Invalid or malformed header: \(header)"
			}
		}
	}

	private let key: SymmetricKey

	/// Creates a new `Webhook` instance using a base64-encoded secret.
	///
	/// - Parameter secret: The base64-encoded secret key used for HMAC signing.
	///
	/// ```swift
	///	let webhook = Webhook(secret: "whsec_...")
	/// ```
	public init?(secret: String) {
		guard let secret = Data(base64Encoded: secret.dropPrefix(SECRET_PREFIX)) else { return nil }

		key = SymmetricKey(data: secret)
	}

	/// Creates a new `Webhook` instance using raw secret bytes.
	///
	/// - Parameter secret: The raw secret bytes used for HMAC signing.
	///
	/// > Warning: This method will not strip the standard prefix (`whsec_`) from the secret.
	public init(secretBytes secret: Data) {
		key = SymmetricKey(data: secret)
	}

	/// Verifies the authenticity and integrity of a webhook payload.
	///
	/// This method checks that:
	/// - All required headers are present and valid.
	/// - The payload's timestamp is within a safe tolerance window to prevent replay attacks.
	/// - The payload's signature is valid.
	///
	/// On success, the payload is authentic and untampered, and safe to process.
	///
	/// - Parameter payload: The payload string.
	/// - Parameter headers: The headers containing the webhook metadata and signature values.
	/// - Parameter now: The current time, in seconds since 1970. Defaults to the current system time.
	///
	/// - Throws: `Webhook.Error` if validation fails due to:
	///     - Missing or malformed headers.
	///     - Invalid or expired/future timestamp.
	///     - Signature mismatch.
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

	/// Verifies the authenticity and integrity of a webhook payload.
	///
	/// This method checks that:
	/// - All required headers are present and valid.
	/// - The payload's timestamp is within a safe tolerance window to prevent replay attacks.
	/// - The payload's signature is valid.
	///
	/// On success, the payload is authentic and untampered, and safe to process.
	///
	/// - Parameter payload: The request payload data, which must be UTF-8 encoded.
	/// - Parameter headers: The headers containing the webhook metadata and signature values.
	/// - Parameter now: The current time, in seconds since 1970. Defaults to the current system time.
	///
	/// - Throws: `Webhook.Error` if validation fails due to:
	///     - Missing or malformed headers.
	///     - Invalid or expired/future timestamp.
	///     - Signature mismatch.
	public func verify(payload: Data, headers: Headers, now: TimeInterval = Date().timeIntervalSince1970) throws(Error) {
		guard let payload = String(data: payload, encoding: .utf8) else { throw .invalidPayload }

		try verify(payload: payload, headers: headers, now: now)
	}

	/// Generates a versioned HMAC-SHA256 signature for the given payload and metadata.
	///
	/// - Parameter id: A unique identifier for the webhook event or delivery
	/// - Parameter payload: The raw payload string to be signed.
	/// - Parameter timestamp: The UNIX timestamp (in seconds) to be included in the signature. Defaults to the current system time.
	///
	/// - Returns: A signature string, conforming to the Standard Webhooks specification.
	public func sign(id: String, payload: String, timestamp: TimeInterval = Date().timeIntervalSince1970) -> String {
		let toSign = "\(id).\(Int(timestamp)).\(payload)"
		let signed = HMAC<SHA256>.authenticationCode(for: Data(toSign.utf8), using: key)

		let encoded = Data(signed).base64EncodedString()

		return "\(SIGNATURE_VERSION),\(encoded)"
	}

	/// Generates a versioned HMAC-SHA256 signature for the given payload and metadata.
	///
	/// - Parameter id: A unique identifier for the webhook event or delivery
	/// - Parameter payload: The raw payload data to be signed, which must be UTF-8 encoded.
	/// - Parameter timestamp: The UNIX timestamp (in seconds) to be included in the signature. Defaults to the current system time.
	///
	/// - Returns: A signature string, conforming to the Standard Webhooks specification.
	public func sign(id: String, payload: Data, timestamp: TimeInterval = Date().timeIntervalSince1970) throws(Error) -> String {
		guard let payload = String(data: payload, encoding: .utf8) else { throw .invalidPayload }

		return sign(id: id, payload: payload, timestamp: timestamp)
	}
}

public extension Collection where Element == Webhook {
	/// Generates a versioned HMAC-SHA256 signature for the given payload and metadata.
	///
	/// - Parameter id: A unique identifier for the webhook event or delivery
	/// - Parameter payload: The raw payload string to be signed.
	/// - Parameter timestamp: The UNIX timestamp (in seconds) to be included in the signature. Defaults to the current system time.
	///
	/// - Returns: A signature string, conforming to the Standard Webhooks specification.
	func sign(id: String, payload: String, timestamp: TimeInterval = Date().timeIntervalSince1970) -> String {
		map { $0.sign(id: id, payload: payload, timestamp: timestamp) }.joined(separator: " ")
	}

	/// Generates a versioned HMAC-SHA256 signature for the given payload and metadata.
	///
	/// - Parameter id: A unique identifier for the webhook event or delivery
	/// - Parameter payload: The raw payload data to be signed, which must be UTF-8 encoded.
	/// - Parameter timestamp: The UNIX timestamp (in seconds) to be included in the signature. Defaults to the current system time.
	///
	/// - Returns: A signature string, conforming to the Standard Webhooks specification.
	func sign(id: String, payload: Data, timestamp: TimeInterval = Date().timeIntervalSince1970) throws -> String {
		try map { try $0.sign(id: id, payload: payload, timestamp: timestamp) }.joined(separator: " ")
	}
}
