import Foundation

struct TunnelStatus: Codable {
    enum State: String, Codable {
        case idle
        case starting
        case running
        case stopping
        case stopped
        case failed
    }

    var state: State
    var packetsFromSystem: UInt64
    var packetsToSystem: UInt64
    var bytesFromSystem: UInt64
    var bytesToSystem: UInt64
    var lastError: String?

    static var idle: TunnelStatus {
        TunnelStatus(
            state: .idle,
            packetsFromSystem: 0,
            packetsToSystem: 0,
            bytesFromSystem: 0,
            bytesToSystem: 0,
            lastError: nil
        )
    }
}
