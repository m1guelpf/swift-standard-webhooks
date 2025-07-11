import Testing
import Foundation
@testable import StandardWebhooks

@Test("Can sign webhook")
func sign() throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	#expect(
		webhook.sign(
			id: "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk",
			payload: #"{"email":"test@example.com","username":"test_user"}"#,
			timestamp: 1_649_367_553,
		) == "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw="
	)

	#expect(
		try webhook.sign(
			id: "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk",
			payload: Data(#"{"email":"test@example.com","username":"test_user"}"#.utf8),
			timestamp: 1_649_367_553,
		) == "v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw="
	)
}

@Test("Can verify webhook")
func verify() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let signature = webhook.sign(id: msgId, payload: payload)

	try webhook.verify(payload: payload, headers: getHeaders(id: msgId, signature: signature))
	try webhook.verify(payload: Data(payload.utf8), headers: getHeaders(id: msgId, signature: signature))
}

@Test("Fails to verify an invalid signature")
func verifyInvalidSignature() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msg_id = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let signature = "v1,R3PTzyfHASBKHH98a7yexTwaJ4yNIcGhFQc1yuN+BPU="
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	#expect(throws: Webhook.Error.invalidSignature) {
		try webhook.verify(payload: payload, headers: getHeaders(id: msg_id, signature: signature))
	}
}

@Test("Fails to verify a partial signature")
func verifyPartialSignature() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let signature = webhook.sign(id: msgId, payload: payload)

	// Just `v1,`
	#expect(throws: Webhook.Error.invalidSignature) {
		try webhook.verify(
			payload: payload,
			headers: getHeaders(id: msgId, signature: "\(signature.split(separator: ",", maxSplits: 1).first!),")
		)
	}

	// Non-empty but still partial signature (first few bytes)
	#expect(throws: Webhook.Error.invalidSignature) {
		try webhook.verify(payload: payload, headers: getHeaders(id: msgId, signature: String(signature.prefix(8))))
	}
}

@Test("Fails to verify an invalid timestamp")
func verifyInvalidTimestamp() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let signature = webhook.sign(id: msgId, payload: payload)

	#expect(throws: Webhook.Error.futureTimestamp) {
		try webhook.verify(
			payload: payload,
			headers: getHeaders(id: msgId, signature: signature, timestamp: Date().timeIntervalSince1970 + (TOLERANCE_IN_SECONDS + 1))
		)
	}

	#expect(throws: Webhook.Error.timestampTooOld) {
		try webhook.verify(
			payload: payload,
			headers: getHeaders(id: msgId, signature: signature, timestamp: Date().timeIntervalSince1970 - (TOLERANCE_IN_SECONDS + 1))
		)
	}
}

@Test("Supports verifying with multiple signatures")
func verifyMultipleSignatures() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let signature = webhook.sign(id: msgId, payload: payload)

	let multipleSignatures = [
		"v1,tFtCZ5RDCPxzWQRWXWPgrCgE2frDBe9gjpbWQxnVfsQ=",
		"v1,Mm7xgUVICxZfQ3bgf0h0Dof65L/IFx+PnZvnDWPCX6Q=",
		signature,
		"v1,9DfC1c3eeOrXB6w/5dIDydLNQaEyww5KalE5jLBZucE=",
	].joined(separator: " ")

	try webhook.verify(payload: payload, headers: getHeaders(id: msgId, signature: multipleSignatures))
}

@Test("Fails to verify multiple invalid signatures")
func verifyInvalidSignatures() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let multipleSignatures = [
		"v1,tFtCZ5RDCPxzWQRWXWPgrCgE2frDBe9gjpbWQxnVfsQ=",
		"v1,Mm7xgUVICxZfQ3bgf0h0Dof65L/IFx+PnZvnDWPCX6Q=",
		"v1,9DfC1c3eeOrXB6w/5dIDydLNQaEyww5KalE5jLBZucE=",
	].joined(separator: " ")

	#expect(throws: Webhook.Error.invalidSignature) {
		try webhook.verify(payload: payload, headers: getHeaders(id: msgId, signature: multipleSignatures))
	}
}

@Test("Fails to verify when headers are missing")
func verifyMissingHeaders() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = #"{"email":"test@example.com","username":"test_user"}"#

	let signature = webhook.sign(id: msgId, payload: payload)
	let headers = getHeaders(id: msgId, signature: signature)

	for header in headers.keys {
		var modifiedHeaders = headers
		modifiedHeaders.removeValue(forKey: header)

		#expect(throws: Webhook.Error.missingHeader(header)) {
			try webhook.verify(payload: payload, headers: modifiedHeaders)
		}
	}
}

@Test("Fails when payload is not valid UTF-8")
func verifyInvalidPayload() async throws {
	let webhook = Webhook(secret: "whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD")!

	let msgId = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk"
	let payload = Data([0xFF, 0xFE, 0xFD]) // Invalid UTF-8 payload

	#expect(throws: Webhook.Error.invalidPayload) {
		try webhook.sign(id: msgId, payload: payload)
	}

	#expect(throws: Webhook.Error.invalidPayload) {
		try webhook.verify(payload: payload, headers: getHeaders(id: msgId, signature: "test-signature"))
	}
}

private func getHeaders(id: String, signature: String, timestamp: TimeInterval = Date().timeIntervalSince1970) -> [String: String] {
	return [
		HEADER_WEBHOOK_ID: id,
		HEADER_WEBHOOK_SIGNATURE: signature,
		HEADER_WEBHOOK_TIMESTAMP: "\(Int(timestamp))",
	]
}
