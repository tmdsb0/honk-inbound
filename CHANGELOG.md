# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries live in [changes/](changes/) until release.

## [0.2.0] - 2026-11-17

### Added

- A group's `detour` is a writable field over the API: a `PATCH` may set or clear it and the group's capabilities list it, so the panel can offer the picker instead of the operator editing the file by hand.
- Formal releases attach `.deb`, `.rpm` and Arch Linux packages for `x86_64` and `aarch64`, which install `honk-core`, `honk-core.service` and an example configuration.
- Formal releases attach the static musl full archive for `aarch64` beside `x86_64`, so ARM gateways run the same build.
- `masque://` share links now carry the parameters the node form writes: `network` (`h2`, or `h3`/`quic` for the QUIC carrier), `private-key`, `public-key`, `ip`, `ipv6`, `mtu`, `remote-dns-resolve` and `dns`, with `sni` / `insecure` handled by the shared TLS pass. Previously the parser read only the endpoint, so a hand-written or UI-generated MASQUE link arrived with no key material and no tunnel address.
- A MASQUE link enables TLS implicitly: the tunnel is always TLS, and a link that names no `security` must not end up dialling in the clear. An unknown `network` value keeps the protocol default rather than failing the node, and `h3` is accepted as another spelling of `quic`.
- A node may name the node it dials out through. A node written into the configuration carries it on its share link as `?dialer-proxy=front`; Clash subscriptions read `dialer-proxy`, and sing-box and JSON outbounds read `detour`. The stream protocols dial the path before TLS, and the QUIC protocols (Hysteria2, TUIC, Juicity) run over the framed UDP path the detour hands back instead of binding a socket of their own.
- A detour may name a policy group as well as a node. The group is resolved on each dial rather than when the generation is built, so the front follows the group's current choice: switching a selector, or a fallback failing over, moves the chain without a reload.
- `dialer-proxy` is now read from a share link written into the configuration, which is the one place an operator writes a node by hand. Previously only a subscription's nodes could name a detour.
- A policy group may carry a detour of its own, written as `detour:` in its block. Whatever member the group then picks is dialled through the node or group named, and reached on its own path when the group is not the one the flow came through — so the same node can be chained in one group and direct in another. The name is validated like a node's, and cycles through groups are refused at load.
- A group's detour is honoured by Trojan, VMess, SOCKS5 and VLESS. VLESS carries it on its plain stream path; its H2 and Cool paths refuse, because they put many flows on one tunnel the node keeps and a tunnel opened over some other path is not one this flow may join.
- A REALITY node may now be dialled through a detour. Its fallback handshake re-dials the same peer, and that re-dial goes through the detour too: sending it out of the real interface would leak the flow at the exact moment the handshake looks most suspicious. The direct re-dial is what happens when there is no detour.
- A group's detour also carries AnyTLS, Hysteria2, TUIC and Juicity. Each of them keeps sessions or connections that ride many flows at once, and the pooled ones belong to the path that opened them, so a detoured dial builds its own instead of borrowing: a handshake per connection rather than a carrier that belongs to another flow's path.
- MASQUE is carried too, which is the one that needed a change of shape rather than a new entry point. A MASQUE tunnel is the path: its carrier is the single connection to the endpoint that every flow on the node shares, so a flow told to ride a detour cannot use the tunnel that was opened over the node's own path. A node therefore keeps one tunnel per path instead of one in total, each with its own TUN device and its own default-route metric — one metric was the real obstacle, since a second tunnel sharing it would have overwritten the first's default route.
- A detour handed to a MASQUE tunnel is no longer dropped when the node names none of its own. The carrier was matched on the node's detour first and fell through to a direct dial otherwise, so a group's detour was silently ignored and the node went out of the real interface.
- A MASQUE node can now be latency-probed from the panel. The probe opens its own tunnel through an ephemeral runtime, and that tunnel takes a slot from a high range unique per probe rather than the node's own slot 0 — otherwise the probe's TUN device and default route would collide with the generation's and either fail to open or silently steal the generation's route. The panel's protocol table had been missing MASQUE, which hid the test button; both sides are corrected so a MASQUE node measures the latency the same way every other node does.
- VMess UDP through the protocol's command-UDP request (`0x02`): one association per destination, one AEAD body chunk per datagram in each direction. It is connected UDP, so a UDP flow over VMess works but is not a shared full-cone source.
- VMess follows the `network` field like Trojan: an explicit `network: tcp` keeps the node out of UDP selection, while an omitted value allows both TCP and UDP.

### Changed

- The shipped `honk-core` binary now allocates through jemalloc instead of mimalloc; `-stock` archives still use the system allocator.
- The `honk-core` Cargo feature formerly named `mimalloc` is now `jemalloc`; builds with `--no-default-features` keep the system allocator.
- Release downloads label the default allocator `jemalloc-*` instead of `mimalloc-*`.
- Removed the mimalloc-only `HONK_MI_COLLECT_SECS` and `MIMALLOC_PURGE_DELAY` environment variables and the worker idle-collection machinery they controlled.
- Runtime jemalloc options use `_RJEM_MALLOC_CONF`, not `MALLOC_CONF`: the crate prefixes jemalloc symbols and the environment variable with `_rjem_`.
- Add reloadable `global.shutdown_wait_connections` (default `false`). Set `true` to retain the previous five-second connection grace; mandatory cleanup and native HTTP shutdown are unchanged.
- The embedded doona UI now comes from this project's own doona fork, so its MASQUE latency-test fix ships with the binary instead of waiting for an upstream release.
- The embedded doona UI moves to 0.1.0-rc.8, which drops the negative DNS coverage entry now that honk no longer caches negative answers.

### Fixed

- AnyTLS nodes with `min_idle_session` above one now keep that many idle sessions open. The pool janitor previously reused the idle session it already had and never dialed the rest ([#260](https://github.com/daeuniverse/honk/issues/260)).
- Clash subscriptions that pin a server certificate with `fingerprint` now import it as `tls_pin_sha256` instead of failing the TLS handshake.
- Clash and mihomo VMess nodes that declare `udp: true` are imported with UDP enabled instead of being dropped. This fork implements VMess command-UDP, so the claim is honored (`network: tcp,udp`); `udp: false` still restricts the node to TCP.
- `POST /api/v1/nodes` accepts a share link whose `dialer-proxy` names an existing node or group again. The entry was validated as a document holding only itself, so every detour it named was unresolvable and the create failed with "node detour must name a node, a group or direct"; the entry now runs only the checks that stand on one entry, and the assembled configuration still resolves the references when it activates.
- Switching a chained proxy's front node now takes effect immediately for every protocol, without restarting honk. A reload reuses the runtime of a node whose own config did not change, but its detour binding belonged to the previous generation and could not be replaced, so the new front was ignored; bindings are now rebound (or cleared) on each generation. A MASQUE tunnel is a long-lived carrier opened once over whichever front the group then selected, and its cache was keyed only by group name, so every later flow kept riding the old member's connection; the cache now records the carrier node and rebuilds the tunnel — releasing the old TUN device — as soon as the front changes.
- DNS cache now stores only successful resolutions that yield an address. NXDOMAIN, SERVFAIL, NODATA, CNAME-only answers, rejected answers, and REFUSED synthetics are never cached and never evict an existing positive, so an expired positive keeps serving stale and the next query re-asks upstream.
- Removed the negative cache entirely, including its OpenAPI `negative` coverage and `entry_kinds` entries. Persisted rows without an address are skipped on restore.
- Detour dials now race every resolved address of the target server instead of dialling only the first one, matching direct dials. A dead first address no longer fails the dial, and a REALITY re-dial reuses the address the race already won instead of resolving again. This covers TCP detour dials, MASQUE h2/h3 tunnels, and QUIC nodes dialled through a detour; one raced dial selects a group front once, so a LoadBalance front is not advanced per address tried.
- A node whose detour is not bound in the running generation now fails its dial instead of leaving through the real interface as if nothing were configured.
- A node that names a detour is carried through it exactly once. MASQUE reads the same shared binding as every other protocol, so its own carrier no longer applies the path a second time.
- REALITY is refused on a detour, and so are Hysteria2 obfuscation and port hopping: each needs a socket of this node's own, so applying them through a detour would not do what the configuration asks.
- A detour that names a group is no longer discarded. It used to be dropped with a warning, on the grounds that nothing on the dial path could resolve a group, which meant a subscription carrying `dialer-proxy: <group>` silently configured nothing.
- A SOCKS5 or AnyTLS node that names a detour is now carried by it instead of ignoring it. Both dialled their own socket and never read the binding, so the traffic left through the real interface looking like an ordinary connection — the one thing a detour exists to rule out.
- A Shadowsocks node that names a detour now refuses the dial. Its ciphers are built around a real socket, so it cannot be carried; failing loudly is better than going direct without saying so.
- Bound each DNS cache shard's answer bytes to `max(entry capacity × 1 KiB, 65,535 bytes)`, evicting LRU entries when large answers fill the budget.
- Inline DNS cache insert/remove accounting in size-optimized builds.
- DNS upstreams that dial through a node which names `dialer-proxy` no longer fail with `detour ... is not bound in this generation`. The DNS runtime fork rebuilt every node runtime without the detour bindings, and since the fork is rebuilt on every boot, restarting did not help. The fork now carries the parent generation's bindings over.
- A group that draws its members from another group with `filter: group(X)` now inherits X's `detour:` when it names none of its own. Previously a group detour was looked up only on the group the flow hit, so every group referring to a chained group — `Proxy`, `Google`, `YouTube` and the rest in a typical split-routing config — used the same node as `Final` but dialled it directly, bypassing the front. `filter: group(X)` is a reference edge rather than a copied node list, so borrowing X's selection now also borrows how that selection leaves the machine.
- An explicit `detour:`, including `direct`, still wins; inheritance follows nested groups in declaration order and cannot loop. Because the lookup lives in `group_detour()`, TCP and UDP dials and the Clash/native delay probes all take the same front.
- A TCP health-check cooldown no longer skips a node's due UDP probe, and an emergency TCP probe no longer clears UDP cooldowns.
- Health-check cycles skip worker creation when both TCP and UDP probes are cooling down.
- A manual delay test on a node that names `dialer-proxy` now rides that front instead of failing with `detour ... is not bound`, matching what automatic probing already reported.
- MASQUE tunnels that a reused runtime kept from an earlier generation are reclaimed on reload, so their TUN devices and routes no longer linger until a restart. Flows hold a reference to the tunnel they ride, so reloading does not tear an active connection's device away.
- When NFQUEUE is unavailable at startup, configuration writes and reloads are no longer refused because `global.nfqueue_enable` needs a restart; the reloaded configuration keeps NFQUEUE disabled.
- A manual HTTP or DNS probe of a node that names its own front (dialer-proxy) now rides that front the way real flows do, instead of failing with a generic `probe_failed`; the DNS probe over UDP rides it too, and a failed probe attempt logs the actual cause.
- A node that names `dialer-proxy` no longer fails with `detour ... is not bound in this generation` right after a reload that added the detour: the connection pool still offered bare TCP sockets it had opened before, and the pooled path has no runtime to read the binding from. Nodes on a detour now skip the pools and dial through the generation that carries the binding.
- Group probes measure up to 10 members at once, so a slow member no longer leaves later members at `deadline`.
- Probe target resolution failures are logged with the host and DNS error instead of appearing only as `address_unavailable`.
- Probe targets fall back to bootstrap DNS when the running DNS configuration cannot answer, so `asis` routing no longer reports every probe as `address_unavailable`.
- A refused `--store db` start no longer leaves an empty state database, or its data directory, behind.
- A subscription that shares a node with another subscription now loads its other nodes; the shared node stays with the subscription that published it first.
- Retry failed subscription fetches with exponential backoff instead of waiting for the full refresh interval.
- A subscription that publishes an endpoint already written by hand in `config.dae` now loads: the hand-written node and the imported copy are two distinct outbounds instead of colliding on one node ID and rejecting the whole provider with `duplicate-node-id`.
- Two providers serving the same endpoint still share one identity, so the existing first-publisher-wins rule is unchanged.
- VLESS nodes imported from a subscription keep UDP enabled when the proxy omits `udp`, matching the same endpoint written as a local `node {}`. Only an explicit `udp: false` restricts the node, in both base64 share-link lists and mihomo/Clash YAML.
- Traffic on L3-typed interfaces whose driver still sends Ethernet frames (for example RAWIP cellular modems) is intercepted again.
- A UDP flow reaching a group that names `detour:` now dials through that front instead of the node's own path. The group detour was resolved only on the TCP dial path, so every UDP flow — QUIC/HTTP3, DNS-over-QUIC, UDP associates — silently left through the node's direct connection even while TCP traffic on the same group was chained.
- MASQUE, Hysteria2, TUIC, Juicity, Trojan and AnyTLS now carry a group's detour on UDP. A detoured flow builds its own tunnel, QUIC client or session instead of borrowing a pooled or shared-source carrier opened over another path, and a MASQUE UDP socket now keeps its tunnel alive so reload pruning cannot delete the device from under a live flow. Protocols that cannot carry a detour refuse the dial rather than quietly going direct.
- A VLESS node that names `dialer-proxy` now dials through it. The plain stream path ignored the node's own detour and every dial failed with `detour ... is not bound in this generation`; only a group's detour reached a VLESS member.
- Mask the rule expression, chain and start time in the partial connections view; the tracker fallbacks for those fields now only apply to the full detail view.

### Security

- Clear RUSTSEC-2026-0385 by locking `ctutils` to 0.4.7, so AES-GCM mask generation and `u128` comparisons use constant-time helpers.

### Internal

- Move the aya family to userspace `aya` 0.16, `aya-obj` 0.6, `aya-log` 0.4 and kernel-side `aya-ebpf` 0.3, adapting call sites to the new map, loader and TC context APIs while preserving programs, map names and shared binary layouts.
- Make shared payload padding explicit and restrict locked-value `Pod` implementations to the three audited payloads; reject stale BTF schemas without changing existing field offsets or map-value sizes.
- Fix the clippy findings the 1.99 toolchain reports with `-D warnings`: `is_multiple_of` for the rate-limited log counters, collapsed `if let` chains, `is_none_or` for the inbound-not match, a removed dead `FetchFailure` re-export, a single-element benchmark loop, and `&[b'x'; 64]` instead of `&vec![b'x'; 64]`.
- The quoted-name routing test drops the unreachable `RoutingOutbound` arm: the enum has only the `Simple` variant, so the test asserts on `as_str()` instead.
- The detour/QUIC tests follow the refactors they lagged behind: the QUIC client test reads the renamed `dial_endpoint`, the Hysteria2 test covers port-hopping refusal now that obfuscation rides a detour, and the packet-transport test expects wrong-source datagrams to be dropped; the tree is formatted with `cargo fmt`.
- Fix the stale native flow and netlink tests: the TCP close test now expects the row reclaimed at retirement admission, the UDP removal test asserts the tombstone is already reclaimed after a failed cleanup, and the netkit fallback test accepts EINVAL and ENOSYS as missing-driver signals.

## [0.1.0-beta.4] - 2026-10-30

### Added

- `ui: 'embedded-lite'` serves doona lite from the binary, and full builds embed doona 0.1.0-rc.4 with both editions. (#363)

### Changed

- Negative cache-hit outcome expiry uses the stored deadline, excluding preferred-family waits without reconstructing the deadline from a rounded TTL. Wire TTLs and routing behavior are unchanged. (#390)
- Clash `/stats.dns` reports DNS socket admission refusals and timeouts, proxy admission timeouts, and idle resources selected for pressure retirement, without per-query warnings. (#390)
- DNS UDP client admission now shares one process-wide budget across reloads; requests in retiring generations keep their permits until they finish instead of receiving a fresh quota each generation. (#390)
- Tests that replace the process-global bootstrap resolver run in an isolated child process. (#390)
- The lint gates compile the DNS benchmarks. (#390)

### Fixed

- WebSocket and gRPC nodes whose path or service name contains a space now connect instead of failing with "invalid uri character"; non-ASCII text is now normalized to percent-encoded UTF-8 ([#378](https://github.com/daeuniverse/honk/issues/378)). (#382)
- The standalone `dns.bind` UDP listener handles much higher concurrent query load. Up to four supervisors, bounded by the Tokio worker count, receive datagrams in batches of up to eight, and an answer that is ready on its first poll is sent without spawning a task. A recent cache hit with an unchanged address set skips the route-projection locks for up to one second, so its route may expire up to one second later than the cache entry. (#381)
- Sockets owned by upstream DNS use one bounded budget that persists across reloads. Under pressure, idle transports are reclaimed and a busy direct UDP upstream spreads over up to four sockets per address. A query whose upstream cannot obtain a socket is answered with `SERVFAIL`. (#381)
- Concurrent UDP DNS client queries per DNS generation are capped at `min(1536, MemTotal / 4 / 256 KiB)`, replacing the previous cap of at most 256, with a fallback of 1536 when `MemTotal` is unreadable. Above the cap, `dns.bind` answers `REFUSED` and transparent port-53 UDP drops the query. (#381)
- The startup descriptor-budget log replaces `dns_slow` with `dns_sockets` and `dns_udp_queries`. (#381)

### Internal

- Changelog entries come from per-PR fragments in `changes/`, and release notes list the released CHANGELOG section with the embedded doona version. (#364)
- The README follows the doona README layout, with a table of release builds and both kinds of web UI. (#364)
- CI path filters list only the files each lane reads, the release-script tests run on every PR, and the CI report shows unfinished runs as pending. (#364)

## [0.1.0-beta.3] - 2026-10-27

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.3), which list every change. Interface and VLAN handling changed for existing configurations: see the [migration guide](doc/migration/en/v0.1.0-beta.3.md).

### Changed

- honk plans and owns interface hooks per interface index, with type-aware framing and lazy reconciliation. (#352, #353)
- A missing or late interface no longer aborts startup, and TCX links follow device deletion and recreation. (#353)
- Per-device sysctl paths and the `interface_binding` degradation report interface setup failures explicitly.

### Fixed

- Bond interception and replies stay on the logical master, so active-backup failover keeps working while LAN bridge ports remain covered. (#354)
- VLAN-tagged and unsupported frames go to their own upper device. To manage a VLAN subnet, list the VLAN subinterface (for example `eth1.20`); a parent-only configuration no longer black-holes that subnet. (#355)

## [0.1.0-beta.2] - 2026-10-25

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.2), which list every change.

### Changed

- The per-source UDP new-flow budget is 1024/s per CPU.
- The UDP endpoint pool scales with RAM: a quarter of `MemTotal` at 64 KiB per endpoint, capped at 32,768.
- The 64 KiB UDP receive buffers moved out of endpoint and source task futures, cutting per-source and per-destination memory.
- BBRv3 is the default BBR for QUIC, and direct QUIC dials bind fresh sockets to recover from carrier loss.

### Fixed

- All client sources share one reply-socket pool per peer, so more than seven foreign peers no longer kill an ordinary full-cone endpoint or drop replies; flows that end by themselves are no longer fenced.

## [0.1.0-beta.1] - 2026-10-23

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.1), which list every change. Configuration moved since `v0.0.1.beta.84`: see the [migration guide](doc/migration/en/v0.1.0-beta.1.md).

### Added

- The opt-in native API (`native-api`) serves authenticated HTTP and SSE over runtime, sources, DNS, probes and lifecycle, and `native-ui` embeds the web UI. The Clash API remains the default.

### Changed

- AnyTLS uses eight carriers per node, a 1 MiB per-session write budget and single-copy frame serialization, raising upload throughput and lowering CPU and new-stream latency.
- Release archives are split by API (`full`, `clash-api`, `native-api`) and ship with `SHA256SUMS` and build provenance.
- Runtime state lives in `<data_dir>/state/honk.db`, `cache_file.enabled` changed meaning, and download defaults moved to the new `assets` block.

### Fixed

- A cancelled AnyTLS write no longer sends a payload the caller never accepted, and a spread re-election no longer fails a healthy pool or trips its dial breaker.
- OpenWrt kernels start from their external BTF.
- Shared UDP sources survive malformed SOCKS5, Trojan and Juicity datagrams.
- QUIC session tickets honour `skip_cert_verify`, and a reload restores warm carriers and probes.

[Unreleased]: https://github.com/daeuniverse/honk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.4...v0.2.0
[0.1.0-beta.4]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/daeuniverse/honk/compare/v0.0.1.beta.84...v0.1.0-beta.1
