# User Interaction Design

## Purpose

This document defines the intended user interaction model for ObstacleBridge.

It focuses on how operators should experience the product rather than how the internals are implemented.

The main goals are:

- reduce setup complexity
- replace syntax-heavy configuration with guided workflows
- make security posture visible early
- help users reach a safe working configuration without reading the full manual first

This document complements:

- [SERVICE_DEFINITION_DESIGN.md](/home/ohnoohweh/quic_br/docs/SERVICE_DEFINITION_DESIGN.md) for structured service configuration
- [WEBADMIN_DESIGN.md](/home/ohnoohweh/quic_br/docs/WEBADMIN_DESIGN.md) for the current delivered admin surface
- [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md) for secure-link trust and transport protection concepts

## Product stance

ObstacleBridge should feel like a guided networking tool, not a syntax puzzle.

The primary interaction model should be:

1. install and start with `python -m obstacle_bridge`
2. let the runtime detect first start from the default config state
3. open Admin Web onboarding
4. choose a simple goal
5. answer only essential prompts
6. connect and then expose advanced settings progressively

The operator should not need to memorize tuple formats, certificate field lists, or every transport option just to publish one service or secure one deployment.

## Design principles

- ask about goals before asking about fields
- use plain operator language before protocol terminology
- present safe defaults first
- separate basic setup from advanced tuning
- explain why a recommendation matters at the point of decision
- keep the product usable even if the user has not read the full README
- surface security posture early and repeatedly, but without blocking legitimate lab/testing use
- help users choose the most suitable protocol and settings for their environment
- prefer autodetection and autovalidation over unnecessary manual entry
- avoid asking for the same connection inputs multiple times
- let one configured node generate reusable setup material for another node

## Design direction and justification

The interaction design is intentionally moving away from a configuration-first product toward a guided operator-first product.

That direction is justified by the nature of the tool:

- ObstacleBridge combines transport choice, exposure decisions, service mapping, and security posture in one runtime
- many important choices are cross-cutting rather than isolated to one field
- users often know what they want to achieve before they know which protocol or settings are appropriate
- small configuration mistakes can lead to confusing failure modes that are hard to diagnose from syntax alone

The design direction therefore prioritizes:

- guided decisions over raw parameter entry
- validation and recommendations over silent acceptance of risky settings
- reusable setup artifacts over repeated manual input
- visibility of security and troubleshooting posture over hidden internal state

### Why guided interaction matters

Guided interaction is preferred because the tool asks users to make decisions that are operational, not merely syntactic.

Examples:

- choosing `myudp` vs `ws` is not just a protocol dropdown, it is a judgment about the surrounding network
- deciding whether a listener is localhost-only or publicly reachable affects the expected security posture
- choosing between PSK and certificates is a tradeoff between quick deployment and longer-term trust management

A raw config editor can expose those knobs, but it does not help the user choose well.

### Why recommendations and warnings matter

The product should recommend better defaults and warn on risky exposure because:

- many deployments start as experiments and later become semi-permanent
- localhost-only assumptions often drift into broader exposure over time
- operators benefit from incremental hardening guidance rather than only binary pass/fail validation

This is why the security advisor distinguishes:

- acceptable-but-not-ideal local/lab posture
- warning-level real-world exposure without expected protection

### Why reuse matters

Configuration reuse and template connections are important because duplicated input creates avoidable errors.

If a server already knows:

- which transport peers should use
- which hostname or IP they should target
- what security mode is expected

then asking the peer-side operator to re-enter those values manually adds friction without adding value.

### Why troubleshooting context belongs in the interaction design

Troubleshooting is part of user interaction, not only an engineering afterthought.

When something fails, the operator needs fast answers to basic questions such as:

- what exact build is running
- whether the runtime is clean or tainted
- what transport and security mode are active
- whether the path appears unstable

Exposing this context directly in the UI reduces support friction and helps users reason about the system without dropping immediately into logs or source code.

### Why some surfaces stay optional

Not every operator wants the same amount of guidance.

That is why parts of the interaction model should remain optional or configurable:

- startup security advisor popup
- first landing tab
- future Home/setup assistant surfaces

This keeps the product approachable for new users without burdening advanced users who already know their workflow.

## Early implementation direction

The current implementation work has started with a deliberately small slice of this broader interaction vision.

What has been added so far:

- a Security Advisor surface in WebAdmin
- startup-popup behavior for the Security Advisor when findings exist
- direct actions from the Security Advisor into the relevant tab
- a user-facing option to stop showing the Security Advisor automatically on startup, with immediate config persistence
- a Home tab that can reopen the Security Advisor
- a Home-tab shortcut to choose whether startup should open `Home` or `Status`
- build identity visibility, including commit ID and clean/tainted state, as part of troubleshooting context

Why this is a good first slice:

- it puts helpful guidance in front of the user without forcing a full wizard implementation first
- it starts reducing configuration hunting by placing a few important controls where the user feels the need for them
- it establishes the pattern that WebAdmin should guide, explain, and assist rather than only expose raw runtime state
- it already connects security posture, troubleshooting posture, and operator convenience in one place

How this contributes to the long-term vision:

- the Security Advisor is an early form of guided interaction
- the startup popup proves that guidance can appear at the right moment instead of being hidden in a tab
- the Home shortcuts show how frequently used decisions can move closer to the user’s workflow
- build identity visibility supports the troubleshooting-assistant direction by making software state visible directly in the UI

This implementation is intentionally not the end state.

It is a foundation step toward:

- setup assistants
- troubleshooting assistants
- protocol and environment advisors
- reusable server-to-peer setup artifacts
- more task-oriented WebAdmin workflows

## Primary user entrypoint

Admin Web should become the main operating console for normal users.

Recommended first-run experience:

1. user starts the runtime with `python -m obstacle_bridge` and no manual config discussion
2. runtime uses default config path (`ObstacleBridge.cfg`) and treats first run as "new start" when no usable config content exists
3. Admin Web opens to a beginner landing page, not raw config fields
4. primary onboarding asks for a connection invite string (human-shared text, typically base64-like)
5. onboarding asks for admin username/password with a visible checkbox to disable auth intentionally
6. bottom actions offer:
   - Set up this node as a peer server
   - Skip guided setup (I will configure manually)
7. only after the quick path succeeds should advanced controls become prominent

Recommended top-level entry actions:

- Set up a peer server
- Connect this node to a peer server
- Publish a local service
- Publish a service on the remote peer
- Create a TUN tunnel
- Enable SecureLink PSK
- Roll out certificate-based trust
- Add certificates for more clients
- Review current security posture
- Help me choose protocol and settings
- Generate peer setup package
- Import peer setup package
- Open advanced configuration

## Beginner-first onboarding contract

The beginning of the user journey should optimize for "first successful connection" rather than "first complete configuration".

First-run onboarding should therefore prioritize:

- one startup command (`python -m obstacle_bridge`)
- one invite-input field
- one credential step (username/password, with explicit opt-out checkbox)
- one-click role choice (peer server vs guided client connect)

The onboarding should defer advanced topics such as:

- multi-file config layout
- structured service-definition editing
- lifecycle hooks and OS-specific hook commands
- transport fine-tuning and protocol edge options

Those topics remain important, but should be presented only after baseline connectivity is established.

## Interaction layers

The UI should have three layers:

### 1. Guided setup

For first run, common tasks, and low-friction changes.

Characteristics:

- wizard-style
- plain language
- one decision at a time
- strong defaults
- visible recommendations

### 2. Structured editor

For operators who know what they want but still benefit from typed forms.

Characteristics:

- service rows and structured sections
- protocol-aware forms
- inline validation
- less narrative than the wizard

### 3. Expert view

For advanced troubleshooting and exact control.

Characteristics:

- raw config visibility
- advanced transport settings
- lifecycle hooks and command templating
- direct field access
- intended as an exception path, not the default

## Configuration reuse and handoff

The interaction design should reduce duplicate data entry between server and peer setup.

When a server or listener has been configured, the product should be able to generate reusable connection material that helps create a fitting peer/client configuration.

This should reuse already-known values such as:

- transport choice
- peer address and port
- secure-link mode expectations
- trust-material expectations
- deployment naming
- recommended service publication side

The user should not need to type the same endpoint and transport information again on the peer side if the server-side setup already knows it.

## Template connections

The product should support template connections.

A template connection is a reusable handoff artifact that describes how another node should connect to a prepared deployment.

It is not necessarily the full runtime config of either side. It is a bootstrap package for generating a matching peer configuration with minimal repeated input.

Suggested template-connection contents:

- deployment name
- intended node role
- recommended transport
- fallback transports if relevant
- peer hostname or IP
- peer port
- expected secure-link mode
- whether PSK or certificate material is still required
- optional service-publication hints
- optional Admin Web recommendations

## Reuse artifacts

The server-side setup should be able to export connection material in operator-friendly forms.

Recommended output forms:

- JSON template file
- QR code
- clipboard-friendly connection payload

The strongest initial design is a canonical JSON template payload that can also be rendered as a QR code.

## Import-assisted peer setup

When a peer imports a template connection, the assistant should pre-fill:

- transport choice
- peer address and port
- secure-link mode
- expected trust posture
- recommended service side
- suggested deployment naming

The assistant should then ask only for node-local values such as:

- should this peer publish local services
- should Admin Web be enabled here
- where local certificate files exist on this node
- whether the user wants to accept the imported recommendation as-is

## Security considerations for reusable setup artifacts

Reusable setup artifacts must improve convenience without leaking secrets.

Recommended default rules:

- do not export `admin_web_password`
- do not export `secure_link_psk` in plaintext by default
- do not export private keys
- do not export certificate private material
- clearly separate shareable connection metadata from secret material

The default export should therefore be a non-secret connection template plus a clear explanation of what still needs to be supplied separately.

## Setup assistant

The setup assistant is the centerpiece of the interaction design.

It should be task-oriented, not feature-oriented.

Opening question:

- What do you want to do today?

### Assistant design goals

- get a working baseline deployed quickly
- hide irrelevant detail until needed
- generate structured config objects automatically
- avoid long text walls
- let the user pause and resume
- make review easy before changes are applied
- recommend suitable protocols and settings instead of expecting the user to know them already
- validate settings continuously so users are less likely to save a broken or unsuitable setup

## Protocol and settings advisor

An important part of the interaction design is helping the user determine the most suitable protocol and related settings.

Most users should not have to choose between `myudp`, `tcp`, `ws`, and `quic` by reading documentation alone.

The product should include a protocol and settings advisor that:

- asks a few environment-focused questions
- inspects the local node and active config where possible
- recommends a best starting protocol
- suggests related settings such as bind strategy, port behavior, and security mode
- validates whether the chosen settings are plausible before apply
- presents fallback options if the preferred choice may fail

This advisor should appear:

- as a standalone landing-page action
- inside the setup assistant when transport or role choices matter
- in advanced configuration when the user wants to re-evaluate an existing setup

## Protocol recommendation model

The recommendation flow should begin with intent and environment, not with protocol names.

Suggested questions:

- Is this node mainly a listener/server or a connecting client?
- Is inbound connectivity available on this node?
- Is the path likely to be restrictive, proxy-heavy, or DPI-filtered?
- Do you want best performance or best compatibility as the first choice?
- Do you expect UDP to work on this path?
- Is HTTP(S)-shaped traffic more likely to pass than raw UDP or TCP?
- Is this a lab setup, a private deployment, or an internet-facing deployment?

The product should then turn those answers into a recommendation.

### Example recommendation patterns

- prefer `myudp` when:
  - UDP is likely available
  - performance and resilience matter
  - the user is not specifically constrained to HTTP(S)-shaped traffic
- prefer `ws` when:
  - restrictive environments or proxies are likely
  - HTTP(S)-shaped traffic is more likely to pass
  - the user wants the most compatibility-oriented first try
- prefer `tcp` when:
  - the path is relatively normal
  - simplicity is preferred
  - the user does not need WebSocket-shaped traffic
- prefer `quic` when:
  - UDP is likely available
  - modern UDP-based transport behavior is desired
  - the environment is not known to block QUIC/UDP

The recommendation should always be presented as:

- recommended first choice
- why it fits
- fallback options

## Autodetection concept

The product should use available local signals to reduce manual work.

Autodetection should be best-effort, transparent, and easy to override.

Suggested autodetection areas:

### Local addressing

- detect local IPv4 and IPv6 addresses
- suggest safe Admin Web defaults such as `127.0.0.1`
- detect broad bind choices such as `0.0.0.0` or `::`
- suggest likely listener addresses based on local interfaces

### Reachability and identity detection

- detect likely public IP address where feasible
- help determine a likely public-facing FQDN when the operator already uses one
- distinguish local bind address from externally reachable address
- help the user confirm which address or hostname peers should actually use
- detect when the node appears to be behind NAT or another forwarding layer

### Existing runtime posture

- detect whether the node is already configured as listener or client
- detect whether peer target settings already exist
- detect whether services are already configured
- detect whether Admin Web auth is enabled
- detect the current `secure_link_mode`

### Transport prerequisites

- detect whether optional dependencies for selected transports appear available
- detect whether certificate-mode required file paths are configured
- detect whether TUN prerequisites are likely absent on the current OS
- detect obviously invalid bind/port combinations

### Environment clues

- infer whether the node is probably internet-facing from bind choices
- infer whether the current setup deserves stronger security recommendations
- infer when a chosen protocol looks mismatched to the user’s stated environment
- infer whether a proxy is likely involved in the path
- infer whether the node appears to be behind NAT or reverse forwarding

### Path and quality detection

- probe whether the node appears to sit behind an HTTP proxy for relevant transports
- detect whether direct reachability assumptions are likely wrong
- run lightweight peer-to-server path checks when both sides are available
- estimate whether packet loss, high latency, or repeated reconnects are already visible
- use observed path quality to influence transport recommendations and warnings

## Autovalidation concept

The assistant should validate continuously while the user edits settings.

Validation should happen in three layers:

### 1. Field validation

- required values present
- port range valid
- address syntax valid
- protocol-specific service fields valid

### 2. Configuration validation

- listener/client settings coherent for the chosen role
- secure-link settings match the selected secure mode
- service definitions belong on the intended side
- Admin Web bind and auth choices make sense together

### 3. Environment validation

- required files appear to exist
- dependencies appear available
- bind addresses are plausible on this host
- selected TUN mode is plausible on this OS
- detected public reachability assumptions match the proposed role
- proxy-related assumptions are plausible for the chosen transport
- observed path quality does not obviously contradict the recommended transport

Validation should be fix-oriented and explain what to do next.

## Network-environment detection

The assistant should help the user understand the environment the node is actually running in.

Important examples:

- what public IP address appears reachable from outside
- whether an FQDN is already available and more suitable than a raw IP
- whether the node seems to sit behind NAT
- whether outbound access appears to use a proxy
- whether the path between peer and server already shows packet loss or instability

The goal is not perfect network discovery. The goal is to reduce operator guesswork and improve first-try success.

### Public IP and FQDN assistance

For server-style setups, the assistant should help answer:

- What address should peers use to reach this server?

Recommended behavior:

- show local bind addresses separately from likely external addresses
- allow operator confirmation of the proposed public IP or hostname
- prefer an operator-supplied FQDN over a raw detected public IP when both exist
- explain when the selected bind address is not the same thing as the peer-facing address

Example operator guidance:

- This server listens on `0.0.0.0:4443`, but peers will likely need to use `bridge.example.com:4443`.

### Proxy detection assistance

For client-style setups, the assistant should help answer:

- Does this environment likely require proxy-aware transport choices?

Recommended behavior:

- inspect relevant proxy environment settings where available
- detect existing platform proxy hints where available
- ask the operator to confirm whether outbound traffic normally goes through a proxy
- increase preference for `ws` when proxy-like conditions are detected

Example operator guidance:

- This node appears to use an HTTP proxy for outbound traffic. Start with `ws` for best compatibility.

### Packet-loss and path-quality assistance

When peer and server can both participate, the product should support lightweight path-quality checks.

Recommended uses:

- estimate whether the path already shows packet loss
- observe whether repeated reconnects or failed handshakes are occurring
- identify whether latency is unusually high
- adjust protocol recommendations and troubleshooting hints based on observed path quality

Example operator guidance:

- Recent checks suggest elevated packet loss on this path. `myudp` may still perform well, but you should expect more retransmission activity.

Or:

- This path looks stable and low-loss. `tcp` or `myudp` are both reasonable first choices.

## Recommended protocol selection UX

When the user reaches transport selection, the UI should do more than show a dropdown.

It should show:

- recommended protocol
- rationale
- strengths
- likely limitations
- fallback options

Example:

- Recommended: `ws`
- Why: This setup looks likely to need HTTP(S)-shaped traffic compatibility.
- Fallbacks: `tcp`, then `myudp`

Or:

- Recommended: `myudp`
- Why: You selected performance/resilience and this environment appears likely to support UDP.
- Fallbacks: `quic`, then `ws`

## Assisted setting generation

After recommending a protocol, the assistant should help generate the surrounding settings.

Examples:

- suggest listener bind addresses
- suggest peer-facing public IP or FQDN for exported connection templates
- suggest ephemeral client local ports where appropriate
- suggest localhost-only Admin Web by default
- suggest SecureLink PSK for quick hardening
- suggest certificate mode for deployment-grade trust
- suggest which side should host the published service

The user should start from a sensible generated baseline and then refine it if needed.

### Core assistant flows

#### Flow A: Set up the peer server

Suggested steps:

1. What should this node do?
   Set up a peer server
2. Help me choose the best transport for this environment
3. Which transport should clients use first?
   preselected recommendation with alternatives
4. Which address and port should this server listen on?
   with autodetected or suggested values
5. What public IP or FQDN should peers use to reach this server?
   with autodetected hints and operator confirmation
6. Should Admin Web be enabled on this node?
7. Do you want to protect Admin Web with a password now?
8. Do you want to enable SecureLink now?
9. Which protection level do you want?
   none, PSK, or certificates
10. Do you want to publish a service now?
11. What kind of service is it?
   TCP, UDP, or TUN
12. Run autovalidation on the proposed settings
13. Review generated settings
14. Generate peer setup package?

#### Flow B: Connect this node to a peer server

Suggested steps:

1. What should this node do?
   Connect to a peer server
2. Start from scratch or import a peer setup package?
3. Help me choose the best transport for this environment
4. Which transport should it use?
   preselected recommendation with alternatives
5. Does this environment use a proxy for outbound traffic?
   with autodetected hints where possible
6. What is the peer address and port?
   prefilled if imported
7. Should this client publish services locally, remotely, or both?
8. Do you want to enable SecureLink now?
9. If yes, use PSK or certificates?
10. Run autovalidation on the proposed settings
11. Review generated settings

#### Flow C: Publish a service

Suggested steps:

1. Where should the listener exist?
   on this node or on the connected peer
2. What do you want to tunnel?
   TCP, UDP, or TUN
3. What local interface/address should be created?
4. What target should traffic reach?
5. Should this service be named for easier recognition?
6. Do you want advanced options?
7. Review generated service entry

#### Flow D: Secure the deployment

Suggested steps:

1. What do you want to improve?
   Admin Web security, SecureLink PSK, or certificate-based trust
2. Do you want the fastest protection or the strongest operational model?
3. If fastest:
   guide into Admin password and PSK
4. If strongest:
   guide into certificate prerequisites and rollout sequence
5. Review recommendations and next actions

#### Flow E: Extend certificate rollout

Suggested steps:

1. Is this deployment already using certificate mode?
2. Are you adding a new client or replacing an existing one?
3. Which role should the certificate allow?
4. Where are the root public key and local certificate files managed?
5. Do you want a checklist for generating and installing the new client material?
6. Review rollout steps and resulting runtime config fields

#### Flow F: Help me choose protocol and settings

Suggested steps:

1. What are you trying to do?
   set up a server, connect a client, publish a service, or secure a deployment
2. How restrictive is the network path likely to be?
3. Do you expect UDP to work?
4. Do you prefer best performance or best compatibility?
5. Should this node be reachable from other machines?
6. Is a proxy likely involved in outbound traffic?
7. Should Admin Web be local-only?
8. Do you want quick protection now?
9. The assistant recommends:
   - protocol
   - bind strategy
   - peer-facing address or hostname strategy
   - security mode
   - first service model if relevant
10. Run autovalidation before apply

#### Flow G: Generate or import template connection

Suggested steps:

1. Do you want to export connection settings for another node or import them here?
2. If exporting:
   - choose file, QR code, or both
3. If importing:
   - load template file or scan QR code
4. Review imported or exported connection metadata
5. Show what was intentionally not included
   - secrets
   - private keys
   - local-only node settings

## Security advisor

The product should include a startup security advisor that evaluates the active configuration and shows clear recommendations.

This advisor should appear:

- on first launch
- after startup if security-sensitive settings are weak or absent
- after config changes that materially alter security posture
- on demand from the Admin Web landing page

The advisor should not only say what is missing. It should explain what the operator can do next.

The security advisor should also interact with protocol/settings guidance when exposure or transport choice changes the risk picture.

It should also inspect imported template-driven setups and warn when the local node is still missing the hardening expected by the shared connection template.

## Security advisor goals

- make risky defaults visible
- help the user improve security incrementally
- distinguish lab/testing posture from deployment posture
- recommend the next best improvement instead of only showing warnings
- avoid false reassurance

## Startup checks

The security advisor should inspect current runtime config and classify findings.

Suggested finding levels:

- `critical`
- `recommended`
- `informational`

### Admin surface checks

- Admin Web enabled with authentication disabled
  - recommend setting `admin_web_password`
- Admin Web enabled with empty or missing password
  - recommend setting `admin_web_password`
- Admin Web listening on a non-loopback address without admin auth
  - show a stronger warning
- Admin Web disabled
  - informational only

### SecureLink checks

- overlay in use with `secure_link_mode=off`
  - recommend enabling SecureLink
- `secure_link_mode=psk` with empty or obviously weak PSK
  - recommend setting a stronger PSK
- `secure_link_mode=psk`
  - recommend certificate mode as the stronger deployment model when appropriate
- `secure_link_mode=cert` with missing required file paths
  - show a blocking configuration problem
- `secure_link_mode=cert` with revocation source unset
  - recommend configuring revoked-serial handling if operationally needed

### Deployment-shape checks

- listener/server node exposed publicly without Admin auth
  - strong warning
- listener/server node exposed publicly without SecureLink
  - strong recommendation
- client node configured for remote service publication without SecureLink
  - recommendation
- multiple published services and no admin password
  - recommendation
- imported template implies public or server-like exposure, but local hardening is still incomplete
  - warning or recommendation depending on severity
- chosen peer-facing address does not match likely reachable public address or hostname
  - warn and request confirmation

### Protocol suitability checks

- selected protocol looks mismatched to the user-stated environment
  - recommend a better first choice and explain why
- UDP-oriented transport selected even though the user described the path as likely UDP-hostile
  - recommend `ws` or `tcp`
- TUN selected where local prerequisites are likely absent
  - warn before apply
- proxy hints are present but the chosen protocol does not fit proxy-heavy conditions well
  - recommend `ws` first
- observed packet loss or instability suggests the user should reconsider the first-choice protocol
  - show a recommendation, not only an error

### Template reuse checks

- imported template is incomplete for this node
  - request only the missing local values
- imported template conflicts with local OS or dependency constraints
  - warn and offer adjusted settings
- imported template expects stronger security than the current local config
  - recommend aligning to the template intent

## Security advisor outputs

The advisor should produce:

- one sentence summary of current posture
- a small ordered list of recommended actions
- severity badges
- a direct action button where possible
- a learn-more link only if the user wants detail

Example summary:

- This node is reachable and currently lacks Admin Web password protection and SecureLink.

Example recommendations:

- Set an Admin Web password
- Enable SecureLink PSK now for quick protection
- Plan certificate-based trust for long-term deployment

## Advisor action model

Every recommendation should map to a concrete next step.

Examples:

- `Set Admin Password`
  - opens a focused admin-auth setup dialog
- `Enable SecureLink PSK`
  - opens the secure quick setup flow
- `Prepare Certificate Rollout`
  - opens the certificate guidance flow
- `Review Admin Exposure`
  - opens the admin bind/auth settings
- `Re-evaluate Protocol Choice`
  - opens the protocol and settings advisor
- `Generate Peer Setup Package`
  - opens export actions
- `Import Peer Setup Package`
  - opens template import flow

This keeps the advisor actionable instead of passive.

## Security progression model

The interaction design should support progressive hardening.

Recommended model:

### Stage 1: Minimal bootstrap

- basic listener or client config
- Admin Web possibly enabled
- low barrier to first connection

### Stage 2: Immediate hardening

- set Admin Web password
- enable SecureLink PSK
- confirm listener exposure settings

### Stage 3: Deployment hardening

- migrate to certificate-based trust
- configure revocation source
- establish operational certificate rollout procedures

The product should present these as a maturity ladder rather than an all-or-nothing wall.

## Landing page concept

The Admin Web landing page should become a dashboard for action, not only for status.

Suggested sections:

- Today’s actions
- Security advisor
- Quick start
- Current topology summary
- Recent changes
- Advanced tools

Suggested “Today’s actions” cards:

- Set up peer server
- Connect a client
- Publish a service
- Secure this deployment
- Add another client

## Review and confirmation UX

Before applying changes, the user should see a review step that translates decisions back into understandable language.

The review should answer:

- what will listen where
- what traffic will be tunneled
- whether Admin Web is protected
- whether SecureLink is off, PSK, or certificate-based
- whether services will exist locally or on the peer
- whether this setup was created from an imported template connection
- which values were reused and which were supplied locally

The review should not dump only raw JSON unless the user explicitly switches to advanced view.

## Service management UX

The structured service editor should follow the setup assistant model.

Recommended row summary format:

- `TCP 0.0.0.0:80 -> 127.0.0.1:8080`
- `UDP :::16666 -> 127.0.0.1:16666`
- `TUN obtun0 mtu 1400 -> obtun1 mtu 1400`

Each row should support:

- edit
- duplicate
- disable
- delete
- show advanced details

Future lifecycle-hook support should appear only in an advanced section so common service setup stays simple.

## Certificate guidance UX

Certificate mode is more complex than PSK and needs a dedicated guidance flow.

The product should be honest about that complexity.

Recommended user framing:

- PSK is the quick-start protection option
- certificates are the long-term managed trust option

Certificate guidance should help the user answer:

- Do I already have a deployment root?
- Is this a new deployment or an existing one?
- Am I adding a server or a client?
- Where are the root public key, local certificate, signature, and private key files?
- Do I need to revoke or replace an existing client?

The UI should present rollout checklists and prerequisites rather than pretending certificate management is one click when the supporting material still comes from outside the runtime.

## Troubleshooting assistant

The user interaction model should also include a troubleshooting assistant.

Its purpose is to help the operator understand why something is not working, starting from the most basic diagnostic questions and moving toward more specific guidance.

The troubleshooting assistant should reduce ambiguity and shorten the path from:

- something does not work

to:

- here is the most likely reason
- here is what we currently know
- here is what to check next

## Troubleshooting assistant goals

- identify the exact software state under investigation
- distinguish configuration issues from network-path issues
- distinguish security-policy issues from transport issues
- make common failure patterns visible without reading logs first
- give concrete next actions instead of generic failure text

## Troubleshooting context the assistant should surface

The assistant should gather and present the most important context first.

Recommended initial context:

- build identity
  - commit ID
  - clean or tainted state
  - whether the runtime is running from a Git-identifiable checkout
- node role
  - listener/server or peer/client
- chosen transport and security mode
  - `myudp`, `tcp`, `ws`, or `quic`
  - SecureLink off, PSK, or certificates
- current bind and peer settings
- whether Admin Web is password-protected
- whether the node appears localhost-only or externally exposed
- recent reconnect, retry, or failure indicators
- peer/session health hints
  - latency
  - packet loss indicators where available
  - repeated reconnects
  - last incoming activity

## Build identity as troubleshooting context

Build identity is an important part of troubleshooting, not just a version label.

The assistant should expose:

- commit ID
- whether the checkout is clean or tainted
- whether local tracked or untracked modifications are present

This helps answer:

- What exact software am I looking at?
- Is this a reproducible clean state or a locally modified one?
- Could observed behavior come from local uncommitted changes?

For deployments that do not run from a Git checkout, the assistant should still show whatever build/version stamp is available and clearly indicate when Git-based identity is unavailable.

## Typical troubleshooting questions

The assistant should help the operator answer questions such as:

- Is the server actually reachable from the peer?
- Is the chosen protocol a good fit for this environment?
- Is a proxy likely involved?
- Is packet loss or path instability already visible?
- Is SecureLink missing where it should be enabled?
- Is certificate material missing or invalid?
- Is Admin Web exposed without the expected protection?
- Am I debugging a clean build or a locally modified one?

## Troubleshooting assistant outputs

The assistant should produce:

- a short diagnosis summary
- a compact list of likely causes
- the most relevant observed facts
- concrete next checks or actions

Example:

- Summary: This client is trying to use `myudp`, but the path looks unstable and repeated reconnects are occurring.
- Likely causes:
  - UDP-hostile or lossy path
  - wrong peer-facing address
  - SecureLink mismatch
- Next actions:
  - re-evaluate transport choice
  - verify peer-facing hostname or IP
  - compare SecureLink mode on both sides

## Relationship to the security advisor

The security advisor and troubleshooting assistant are related but different.

- the security advisor asks:
  - Is this deployment configured safely enough?
- the troubleshooting assistant asks:
  - Why is this deployment not working or behaving poorly?

The UI should let the operator move naturally between these two views.

## Relationship to build visibility

Build visibility belongs in the troubleshooting assistant because it is part of the diagnostic baseline.

Recommended presentation:

- always show a compact build badge
- allow the troubleshooting assistant to expand that into more detail
- highlight tainted state so the operator knows the runtime differs from a clean commit

## Troubleshooting assistant actions

Recommended direct actions:

- Open logs
- Re-evaluate protocol choice
- Review security posture
- Review peer settings
- Review service definitions
- Export troubleshooting summary

The operator should be able to move from diagnosis to action in one step.

## Error-prevention approach

The interaction model should prevent the most common mistakes before save.

Examples:

- warn if Admin Web is exposed without auth
- warn if a public listener has no SecureLink
- warn if certificate mode is selected but required files are missing
- warn if a service definition is incomplete
- warn if the user is about to publish services on the wrong side
- warn if the selected protocol is unlikely to match the user’s stated network conditions

Warnings should be contextual and fix-oriented.

Bad pattern:

- Invalid configuration

Better pattern:

- This listener is reachable from outside, but Admin Web authentication is disabled. Set an Admin password or bind Admin Web to localhost.

Another better pattern:

- You selected `myudp`, but you described this path as likely proxy-restricted and UDP-hostile. Start with `ws` and keep `tcp` as the next fallback.

## State model

The user interaction layer should treat setup as stateful work.

Needed capabilities:

- save draft answers before apply
- resume unfinished assistant flows
- distinguish proposed changes from active runtime state
- compare current and proposed configuration
- keep imported template metadata associated with the draft where useful

This reduces fear of experimentation and makes guided flows more practical.

## Accessibility and language

The product language should stay direct and concrete.

Preferred wording:

- What do you want to do today?
- Where should this listener exist?
- What service do you want to reach?
- Do you want quick protection now?
- Do you want to move to certificate-based trust?

Avoid wording that assumes expert prior knowledge as the default.

## Phased delivery

### Phase 1: Security advisor and landing page

- add a landing page with task-oriented entry actions
- add startup security advisor findings and direct actions
- add protocol/settings recommendation hints and validation summaries
- add template connection export/import to the interaction model
- keep existing config/editor paths available

### Phase 2: Setup assistant

- add guided server/client/service/security flows
- add protocol-selection guidance and setting autogeneration
- add server-side peer setup package generation and peer-side import
- generate structured config objects
- add review/apply/save steps

### Phase 3: Structured service management

- replace raw service text editing with typed service forms
- integrate future lifecycle-hook editing into advanced panels
- deepen environment validation and smarter side/protocol recommendations

### Phase 4: Certificate rollout guidance

- add guided certificate onboarding and extension flows
- add deployment checklists and operational reminders

## Validation expectations

This interaction design should eventually be defended by tests that prove:

- the landing page renders task-oriented actions
- the security advisor reports expected findings for insecure and secure configs
- direct-action buttons open the correct setup flows
- protocol recommendations change appropriately for different declared environments
- autovalidation catches invalid or implausible settings before apply
- exported template connections can be imported to prefill matching peer setup
- normal template exports exclude secret values
- wizard flows generate the expected structured config shape
- review screens summarize the intended behavior in operator language
- certificate guidance appears only when relevant and does not expose secret values

## Recommendation

ObstacleBridge should gain a dedicated user interaction layer centered on two ideas:

- a setup assistant that begins with operator goals
- a startup security advisor that inspects the active configuration and recommends concrete hardening steps such as Admin password setup, SecureLink PSK, or certificate-based trust

An equally important part of that interaction layer is helping users choose the most suitable protocol and settings for their environment, then autodetecting and autovalidating as much as possible before configuration is applied.

The product should also reuse setup work across nodes by letting a configured server generate template connections, files, or QR-based setup artifacts that bootstrap a fitting peer configuration without repeating the same inputs.

This keeps the product approachable for first-time users while still guiding serious deployments toward stronger security and more maintainable configuration.
