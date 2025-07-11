import Foundation

extension String {
	/// Returns a new string made by removing the given prefix from the string.
	///
	/// - Parameter prefix: The prefix to remove.
	///
	/// If the string doesn't start with the given prefix, the original string is returned.
	func dropPrefix(_ prefix: String) -> String {
		guard hasPrefix(prefix) else { return self }

		return String(dropFirst(prefix.count))
	}
}
