import Foundation

/// Portable admission policy for service catalogs on a listener that multiplexes
/// more than one authenticated peer. A shared listener cannot bind one local
/// `own_servers` catalog for every child because the target peer is ambiguous.
/// Its `remote_servers` catalog, however, is a per-child control message and is
/// safe when the operator opts in to publishing the same catalog to each peer.
public enum ObstacleBridgeListenerServicePolicy {
    public static func publishesRemoteServices(listenerMode: Bool, explicitlyEnabled: Bool) -> Bool {
        !listenerMode || explicitlyEnabled
    }
}
