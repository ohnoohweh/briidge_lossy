# ConfigAwareCLI Design

## Purpose

This note records the current `ConfigAwareCLI` design as implemented in `src/obstacle_bridge/bridge.py`.

The class is a stdlib-only wrapper around `argparse` that turns the application’s many component-specific CLI options into a single config-aware flow for:

- bootstrap parsing
- JSON config loading
- argparse default distribution
- grouped config dumps
- config-file saving

The design is intentionally internal. Its scalability is a pure implementation property, not an externally observable behavior.

## Scope

This document covers:

- how CLI arguments are registered and grouped by component
- how JSON config files become parser defaults
- how `--dump-config` and `--save-config` reuse the same normalized argument view
- how the code stays maintainable as more components add options

It does not redefine:

- the black-box requirements in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- the runtime ownership split in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
- the behavior of any particular transport, secure-link, or admin feature

## Current boundary

`ConfigAwareCLI` owns the configuration distribution layer, not the runtime behavior that consumes those values.

It currently owns:

- bootstrap flags such as `--config`, `--dump-config`, `--save-config`, `--save-format`, and `--force`
- registrar-driven option discovery
- per-section grouping metadata
- JSON-to-argparse default application
- config save and dump formatting

It does not own:

- transport runtime state
- secure-link session state
- admin web request handling
- business logic for individual CLI options

## Conceptual model

The class uses a three-stage distribution model:

1. bootstrap stage
2. registrar stage
3. normalized config stage

### 1. Bootstrap stage

The first parser only captures the flags needed to locate and describe the config workflow itself.

That early pass keeps the startup path simple and allows the system to know whether it should load a config file, dump the effective config, or save a normalized file before the full parser finishes.

### 2. Registrar stage

Each runtime component contributes its own `register_cli` function.

`ConfigAwareCLI` runs those registrars and records which `dest` values each one added. That recorded mapping becomes the section model used later for grouped dumps and grouped saves.

This is the key distribution pattern:

- component code owns its own option definitions
- the config layer only observes those options after registration
- the config layer never has to duplicate option lists by hand

### 3. Normalized config stage

Once the parser is complete, JSON config data is flattened into parser defaults, then the final parse runs with the normal argparse precedence rules.

That means:

- built-in defaults still exist
- JSON config values act as defaults
- explicit CLI flags still win last

## Scalability

The scalability of this design is internal and structural.

It matters because new components can add options without requiring a second central registry, manual config schema duplication, or hard-coded save/load tables. The config layer scales by observing the parser rather than by re-declaring every option.

Practical consequences:

- adding a new component usually means adding one registrar, not rewriting the config loader
- grouped config output automatically follows the component sections already registered
- save/load support grows with the parser instead of with a parallel handwritten schema
- config maintenance stays manageable as the project accumulates more transports, admin controls, and observability knobs

This is deliberately not a user-visible guarantee. Users should only observe that the application accepts config files, applies defaults, and can dump or save effective settings.

## Config file behavior

Current config handling is JSON-based.

The loader:

- reads the JSON file
- expands environment variables and `~`
- restores encrypted secret fields back into memory
- applies the result as argparse defaults

The saver:

- derives the effective argument set
- groups values by component section when requested
- encrypts secret fields before writing
- emits JSON to disk with stable formatting

## Tradeoffs

Current tradeoff:

- the design favors parser introspection over a handwritten schema
- that makes it easier to scale, but it also means the structure is intentionally indirect

Future options if the config surface grows further:

- add stricter schema validation around grouped sections
- expose a machine-readable config schema export for tooling
- split additional bootstrap-only flags from runtime options if the startup contract becomes more complex

The acceptance bar should remain practical: config files should stay easy to use, and the runtime should keep accepting new component options without requiring a second schema system.