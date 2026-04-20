import Foundation
import Darwin
import Network
import NetworkExtension

final class PacketFlowBridge {
    private let packetFlow: NEPacketTunnelFlow
    private let queue = DispatchQueue(label: "ObstacleBridge.PacketFlowBridge")
    private var connection: NWConnection?
    private var stopped = false
    private var statusUpdate: (TunnelStatus) -> Void
    private(set) var status = TunnelStatus.idle {
        didSet { statusUpdate(status) }
    }

    init(packetFlow: NEPacketTunnelFlow, statusUpdate: @escaping (TunnelStatus) -> Void) {
        self.packetFlow = packetFlow
        self.statusUpdate = statusUpdate
    }

    func start(host: String, port: UInt16) {
        queue.async {
            self.stopped = false
            self.status.state = .starting
            let endpointHost = NWEndpoint.Host(host)
            let endpointPort = NWEndpoint.Port(rawValue: port) ?? 443
            let connection = NWConnection(host: endpointHost, port: endpointPort, using: .tcp)
            self.connection = connection

            connection.stateUpdateHandler = { [weak self] state in
                guard let self = self else { return }
                self.queue.async {
                    switch state {
                    case .ready:
                        self.status.state = .running
                        self.readFromSystem()
                        self.readFrameHeader()
                    case .failed(let error):
                        self.status.state = .failed
                        self.status.lastError = error.localizedDescription
                    case .cancelled:
                        self.status.state = .stopped
                    default:
                        break
                    }
                }
            }

            connection.start(queue: self.queue)
        }
    }

    func stop() {
        queue.async {
            self.stopped = true
            self.status.state = .stopping
            self.connection?.cancel()
            self.connection = nil
            self.status.state = .stopped
        }
    }

    private func readFromSystem() {
        guard !stopped else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            self.queue.async {
                for packet in packets {
                    self.status.packetsFromSystem += 1
                    self.status.bytesFromSystem += UInt64(packet.count)
                    self.sendFrame(packet)
                }
                self.readFromSystem()
            }
        }
    }

    private func sendFrame(_ packet: Data) {
        guard let connection = connection else { return }
        var length = UInt32(packet.count).bigEndian
        let header = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        connection.send(content: header + packet, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.queue.async {
                    self?.status.state = .failed
                    self?.status.lastError = error.localizedDescription
                }
            }
        })
    }

    private func readFrameHeader() {
        guard !stopped, let connection = connection else { return }
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, _, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    self.status.state = .failed
                    self.status.lastError = error.localizedDescription
                    return
                }
                guard let data = data, data.count == 4 else {
                    self.status.state = .failed
                    self.status.lastError = "short packet frame header"
                    return
                }
                let frameLength = data.reduce(UInt32(0)) { partial, byte in
                    (partial << 8) | UInt32(byte)
                }
                self.readFrameBody(Int(frameLength))
            }
        }
    }

    private func readFrameBody(_ length: Int) {
        guard !stopped, let connection = connection else { return }
        guard length > 0 && length <= 65535 else {
            status.state = .failed
            status.lastError = "invalid packet frame length \(length)"
            return
        }
        connection.receive(minimumIncompleteLength: length, maximumLength: length) { [weak self] data, _, _, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    self.status.state = .failed
                    self.status.lastError = error.localizedDescription
                    return
                }
                guard let packet = data, packet.count == length else {
                    self.status.state = .failed
                    self.status.lastError = "short packet frame body"
                    return
                }
                self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
                self.status.packetsToSystem += 1
                self.status.bytesToSystem += UInt64(packet.count)
                self.readFrameHeader()
            }
        }
    }
}
