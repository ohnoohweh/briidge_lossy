# Service Definition Design

## Purpose

This document proposes a structured replacement for the current comma-separated `own_servers` / `remote_servers` service definition format in `ChannelMux`.

The immediate goal is to make service definitions easier to understand, create, validate, and operate from the Admin UI.

The later follow-up goal is to support optional user-defined commands tied to service lifecycle events for UDP, TCP, and TUN services.

This document is intentionally design-first:

- Phase 1 updates service parameter handling and config shape
- Phase 2 implements execution of configured lifecycle commands
- Phase 3 adds guided operator workflows in Admin Web

## Current problem

Today each service definition is encoded as one 6-field comma-separated tuple:

`proto,listen_port,listen_bind,proto,host,port`

Example:

`tcp,80,0.0.0.0,tcp,127.0.0.1,88`

This works for the current minimal mapping, but it scales poorly because:

- field meaning depends on position rather than names
- the same `port` slot means different things for `tcp` / `udp` versus `tun`
- adding optional behavior such as lifecycle hooks would require even more positional fields
- operator mistakes are hard to spot in review
- Admin Web cannot easily present or validate service details as typed fields
- JSON config files already exist, but the current format still behaves like a shell-oriented tuple string
- the user experience is biased toward reading manual syntax instead of answering task-oriented setup questions

## Design goals

- keep `own_servers` and `remote_servers` as the operator-facing catalog concepts
- replace positional tuples with named structured fields in JSON config and Admin Web
- support `udp`, `tcp`, and `tun` with one consistent schema
- reserve explicit space for lifecycle hook definitions without requiring hook execution in Phase 1
- avoid carrying long-term legacy parser and compatibility complexity in the runtime
- keep listener-mode versus client-mode semantics unchanged unless explicitly redesigned later
- make validation errors precise and field-specific
- optimize for operator guidance and low-friction setup in Admin Web rather than shell syntax preservation

## Non-goals for Phase 1

- no hook execution yet
- no shell/process-management policy finalized yet
- no new wire protocol for lifecycle hooks
- no change to current peer-scoped `own_servers` versus `remote_servers` behavior
- no requirement to preserve legacy tuple parsing in the steady-state runtime

## Product direction

This change should be treated primarily as a product-UX improvement, not just a parser refactor.

The intended operator journey should become:

1. start ObstacleBridge with a minimal bootstrap config
2. open Admin Web
3. choose a task-oriented workflow such as:
   - set up a peer server
   - connect this node to a peer server
   - expose a local service
   - expose a service on the remote peer
   - enable SecureLink PSK
   - roll out certificate-based trust
   - extend certificates to additional clients
4. let the UI generate the structured config objects behind the scenes
5. review and save

That means the internal config model should become structured first, so the Admin UI can guide users without forcing them to learn tuple syntax or read the full manual.

## Proposed operator model

The existing catalog names stay the same:

- `own_servers`: local services this instance exposes through the overlay
- `remote_servers`: services this instance asks the connected peer to expose

The change is the shape of each catalog entry and the way operators create it.

Instead of a tuple string, each service becomes a structured object with named sections:

- `name`: optional operator-friendly identifier
- `listen`: how the local/listening side is created
- `target`: where traffic is forwarded
- `lifecycle_hooks`: reserved optional hook definitions for a later phase
- `options`: reserved service-specific extensions that are not part of the base socket pairing

Operators should not be expected to author these objects manually in normal use. The Admin UI should be the primary editor.

## Proposed JSON shape

### Recommended shape

```json
{
  "own_servers": [
    {
      "name": "public-http",
      "listen": {
        "protocol": "tcp",
        "bind": "0.0.0.0",
        "port": 80
      },
      "target": {
        "protocol": "tcp",
        "host": "127.0.0.1",
        "port": 88
      }
    },
    {
      "name": "wg-local",
      "listen": {
        "protocol": "udp",
        "bind": "::",
        "port": 16666
      },
      "target": {
        "protocol": "udp",
        "host": "127.0.0.1",
        "port": 16666
      }
    },
    {
      "name": "site-a-tun",
      "listen": {
        "protocol": "tun",
        "ifname": "obtun0",
        "mtu": 1400
      },
      "target": {
        "protocol": "tun",
        "ifname": "obtun1",
        "mtu": 1400
      }
    }
  ]
}
```

### Hook-ready extension shape

This block is part of the proposed schema now, but Phase 1 only parses, stores, validates, and exposes it. It does not execute anything yet.

```json
{
  "name": "public-http",
  "listen": {
    "protocol": "tcp",
    "bind": "0.0.0.0",
    "port": 80
  },
  "target": {
    "protocol": "tcp",
    "host": "127.0.0.1",
    "port": 88
  },
  "lifecycle_hooks": {
    "listener": {
      "on_created": {
        "argv": ["scripts/service_hook.cmd", "listener-created", "{service_name}"]
      },
      "on_channel_connected": {
        "argv": ["scripts/service_hook.cmd", "listener-connected", "{service_name}", "{channel_id}"]
      },
      "on_channel_closed": {
        "argv": ["scripts/service_hook.cmd", "listener-closed", "{service_name}", "{channel_id}"]
      }
    },
    "client": {
      "before_connect": {
        "argv": ["scripts/service_hook.cmd", "client-before-connect", "{service_name}"]
      },
      "on_connected": {
        "argv": ["scripts/service_hook.cmd", "client-connected", "{service_name}", "{channel_id}"]
      },
      "after_closed": {
        "argv": ["scripts/service_hook.cmd", "client-closed", "{service_name}", "{channel_id}"]
      }
    }
  }
}
```

## Normalized internal model

`ChannelMux.ServiceSpec` is currently fixed to the 6-field tuple model. That is too narrow for future service metadata.

The design should move toward a richer normalized internal object, for example:

```python
@dataclass(frozen=True)
class ServiceEndpoint:
    protocol: Literal["udp", "tcp", "tun"]
    bind: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    ifname: Optional[str] = None
    mtu: Optional[int] = None

@dataclass(frozen=True)
class HookCommandSpec:
    argv: tuple[str, ...]
    timeout_ms: Optional[int] = None
    env: Optional[dict[str, str]] = None

@dataclass(frozen=True)
class ServiceLifecycleHooks:
    listener_on_created: Optional[HookCommandSpec] = None
    listener_on_channel_connected: Optional[HookCommandSpec] = None
    listener_on_channel_closed: Optional[HookCommandSpec] = None
    client_before_connect: Optional[HookCommandSpec] = None
    client_on_connected: Optional[HookCommandSpec] = None
    client_after_closed: Optional[HookCommandSpec] = None

@dataclass(frozen=True)
class ServiceSpec:
    svc_id: int
    name: Optional[str]
    listen: ServiceEndpoint
    target: ServiceEndpoint
    lifecycle_hooks: Optional[ServiceLifecycleHooks] = None
    options: Optional[dict[str, object]] = None
    source_format: Literal["legacy_tuple", "structured_v1"] = "structured_v1"
```

The exact class names may differ, but the important design change is:

- `listen` and `target` become typed endpoint objects
- TUN-specific fields stop being forced into `port`/`host` placeholders
- lifecycle hook configuration lives beside the service definition rather than in separate global options
- internal code can normalize legacy input into this single model

## Protocol-specific rules

### TCP and UDP

For `tcp` and `udp`:

- `listen.protocol` and `target.protocol` are required
- `listen.bind` and `listen.port` are required
- `target.host` and `target.port` are required

### TUN

For `tun`:

- `listen.ifname` and `listen.mtu` are required
- `target.ifname` and `target.mtu` are required
- `bind`, `host`, and `port` are not used for `tun`

This removes the current overloading where TUN squeezes interface names and MTU values into tuple positions named like socket fields.

## Hook schema concept

Phase 1 should reserve lifecycle hook definitions in the service schema even though nothing will be executed yet.

Proposed event names:

- listener side:
  - `on_created`
  - `on_channel_connected`
  - `on_channel_closed`
- client side:
  - `before_connect`
  - `on_connected`
  - `after_closed`

These names match the requested behavior:

- listener socket generated
- accepted/connected socket derived from listening socket connected
- accepted/connected socket closed
- client socket about to be generated
- client socket connected
- client socket closed

## Command-definition concept

For the later execution phase, command definitions should use `argv` arrays rather than one shell string.

Recommended command shape:

```json
{
  "argv": ["scripts/service_hook.cmd", "listener-created", "{service_name}"],
  "timeout_ms": 10000,
  "env": {
    "OB_ROLE": "listener"
  }
}
```

Why `argv` is preferred:

- avoids platform-specific shell quoting ambiguity
- is easier to validate
- is safer than implicit shell execution
- works better with placeholder substitution rules

If shell-string support is ever added later, it should be an explicit opt-in mode rather than the default representation.

## Placeholder concept for Phase 2

The future execution design should support a small explicit placeholder set rather than passing large unstructured state blobs.

Initial placeholder candidates:

- `{service_id}`
- `{service_name}`
- `{catalog}` (`own_servers` or `remote_servers`)
- `{event}`
- `{protocol}`
- `{channel_id}`
- `{bind}`
- `{listen_port}`
- `{target_host}`
- `{target_port}`
- `{ifname}`
- `{peer_id}`
- `{peer_endpoint}`

This placeholder list is intentionally limited so behavior stays understandable and testable.

## Migration strategy

The project does not need to preserve long-term runtime support for the legacy tuple form.

Recommended migration approach:

- the runtime moves to the new structured schema directly
- a separate upgrade script converts existing config files into the new shape
- documentation and Admin Web move immediately to the new model
- if desired, the migration script may also emit warnings or a summary of converted services for review

Why this is preferable here:

- the tool has a focused scope and limited deployment surface
- the codebase stays cleaner without permanent dual-format parsing
- the Admin UI can target one schema only
- test coverage stays simpler
- future feature work such as lifecycle hooks and wizard-generated configs does not need to thread through compatibility branches

The migration script should:

- read existing JSON config files
- detect legacy `own_servers` / `remote_servers` tuple entries
- convert them into structured service objects
- map current TUN tuple conventions into explicit `ifname` / `mtu` fields
- preserve unrelated config fields unchanged
- write the converted file to a new path or with an explicit overwrite flag

The runtime may reject legacy tuple catalogs once the migration tooling and documentation are in place.

## Config and Admin Web impact

This proposal fits the current JSON config system well because `ConfigAwareCLI` already accepts lists and dictionaries from config files.

Phase 1 design expectations:

- flat JSON config continues to work
- grouped JSON config continues to work
- `own_servers` and `remote_servers` become arrays of objects in saved configs
- Admin Web should render service catalogs as structured rows/forms instead of raw JSON-like text fields
- runtime config snapshots should preserve the structured shape so operators can round-trip them without lossy tuple conversion

## Admin Web direction

Admin Web is the most important surface for this change.

The design goal is to reduce user complexity, not to expose internal schema detail.

Recommended UI direction:

- hide raw tuple syntax completely
- default to guided forms and task-oriented flows
- show advanced JSON only as an expert/debug option
- provide protocol-aware editors for `tcp`, `udp`, and `tun`
- provide inline explanations using operator language such as:
  - where should the listener exist
  - what service do you want to reach
  - is this service local or should it be created on the connected peer
  - should this be protected with SecureLink

Recommended service editor structure:

- catalog choice:
  - publish here (`own_servers`)
  - publish on peer (`remote_servers`)
- service type:
  - TCP
  - UDP
  - TUN
- listener side fields
- destination side fields
- optional advanced section
- later optional lifecycle hooks section

The UI should describe intent first and translate that intent into config structure second.

## Quick-start assistant concept

The project should add a quick-start assistant in Admin Web so users can begin from goals instead of documentation.

Example opening prompt:

- What do you want to do today?

Suggested top-level flows:

- Set up the peer server
- Connect this node to a peer server
- Publish a local TCP or UDP service
- Publish a TUN tunnel
- Protect this connection with SecureLink PSK
- Roll out certificate-based trust
- Add certificates for more clients

### Assistant principles

- ask small, concrete questions
- use common words before technical terms
- reveal advanced options only when relevant
- generate a working baseline first
- explain tradeoffs at the decision point rather than in a long manual

### Example basic peer-server flow

1. What do you want to do today?
   Set up the peer server
2. Which transport should new clients use first?
   `myudp`, `tcp`, `ws`, or `quic`
3. On which address and port should this server listen?
4. Do you want to publish any local services now?
5. Which service do you want to tunnel first?
   TCP, UDP, or TUN
6. Do you want to protect this with SecureLink PSK now?
7. Do you want to prepare certificate-based trust now or later?

### Example secure rollout flow

1. Do you want to upgrade this deployment to SecureLink PSK?
2. Do you want to roll out certificates?
3. Is this the first certificate-enabled server in this deployment?
4. Do you want to create certificates for additional clients now?
5. Which clients should receive access?

### Assistant output

The assistant should produce:

- structured runtime config entries
- human-readable review summary before save
- optional next-step checklist
- links to advanced settings only when needed

## Migration plan

### Phase 1: schema and migration tooling

- introduce the structured service schema
- add a one-way config upgrade script for existing files
- keep current runtime service behavior unchanged
- accept and persist structured `own_servers` / `remote_servers`
- remove the need for ongoing runtime legacy-format support
- document lifecycle hook fields as reserved but non-executing

### Phase 2: hook execution

- implement hook invocation at the requested lifecycle events
- define process spawning, timeout, logging, and failure-handling policy
- expose hook results through logs and admin diagnostics
- add black-box regression coverage for listener, client, TCP, UDP, and TUN paths

### Phase 3: UI/editor improvement

- add the quick-start assistant and task-oriented setup flows
- replace raw config text editing for service catalogs with a dedicated structured editor in Admin Web
- add per-protocol validation hints and later hook editing support

## Validation expectations for Phase 1

The first implementation slice should be defended by tests that prove:

- structured JSON service entries load correctly for `tcp`, `udp`, and `tun`
- invalid field combinations fail with precise messages
- structured configs survive `dump-config`, `save-config`, reload, and Admin API snapshot/update round trips
- the migration script converts legacy tuple configs into valid structured configs
- listener mode still ignores `own_servers` / `remote_servers` as today where that behavior is already defined
- no hook command is executed merely because hook fields are present in the configuration

## Open decisions for the later execution phase

- whether hook failures should be best-effort log-only or able to affect channel setup
- whether hooks run synchronously or through background tasks
- concurrency limits for many simultaneous channel events
- stdout/stderr capture policy
- placeholder escaping rules
- whether command environment should include sensitive peer/session data at all

## Recommendation

The project should update service parameter handling first by moving `own_servers` and `remote_servers` to a structured JSON object model and providing a one-way config migration script for existing files.

That gives `ChannelMux` a maintainable configuration boundary, keeps the runtime free from long-term compatibility code, and creates the right foundation for an Admin Web experience that asks users what they want to achieve instead of making them memorize syntax.

Only after that structured model and guided UI direction exist should the runtime implement execution of user-defined commands for listener and client socket lifecycle events.
