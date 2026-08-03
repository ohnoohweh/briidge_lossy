# Known Issues

## TUN helper apply failure on 38.180.143.5

- Status: backlog
- First documented: 2026-08-03
- Affected host: `38.180.143.5`
- Related config: `ObstacleBridge_ishost38.cfg`
- Comparison config: `ObstacleBridge_ishost37.cfg`

### Summary

On `38.180.143.5`, ObstacleBridge can start and keep general connectivity available,
but `obtun0` may remain present without receiving the expected TUN network
configuration.

### Observed behavior

- `obtun0` exists and is `UP`
- TUN IPv4/IPv6 tunnel addresses are not applied
- `tun_helper.runtime.network_applied` remains `false`
- traffic-safety configuration required manual tuning of `excluded_routes`
  to avoid collapsing general internet traffic into `obtun0`

### Known failure point

The failing stage observed from WebAdmin runtime status was:

- `tun_helper.runtime.last_failure.stage = excluded_routes_apply`

The reported failing command was equivalent to:

```bash
ip -4 route replace 38.180.143.5/32 via 146.70.81.179 dev eth0
```

### Why this is notable

The sister host `37.1.192.30` worked with its own config, while
`38.180.143.5` failed when configured for full-tunnel routing plus explicit
self-address excludes. The issue appears in the route-application path rather
than in TUN creation itself.

### Current handling

- kept as backlog for later investigation
- local code experiments were reverted
- current understanding should be treated as diagnostic context, not a shipped
  fix

### Suggested future investigation

- capture `ip addr` and `ip route` output from both hosts at the time of failure
- compare how the helper programs self-address exclude routes on the underlay
  interface
- verify whether `/32` underlay addressing or provider-specific routing semantics
  are involved
