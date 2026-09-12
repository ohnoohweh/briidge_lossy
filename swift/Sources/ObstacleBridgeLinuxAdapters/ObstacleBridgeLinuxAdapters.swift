import Foundation
import ObstacleBridgeCore

/// Linux-only assembly boundary for POSIX networking, TUN, and hook adapters.
/// No privileged or network operation is implemented in the build baseline.
public enum ObstacleBridgeLinuxAdapters {
    public static let platform = "linux"
    public static let runtimeStatus = ObstacleBridgeCoreRuntime.runtimeStatus
}
