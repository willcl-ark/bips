```
  BIP: ?
  Layer: Peer Services
  Title: Coordinatorless IPv4 TCP Hole Punching
  Authors: TBD
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Version: 0.1.0
  Requires: 155, 324, 434
```

## Abstract

This document specifies additional Bitcoin peer connections between IPv4
nodes behind compatible NATs or stateful firewalls. Nodes gossip an
external endpoint and an ephemeral public key through `addrv2`. Two nodes
that retain each other's advertisements derive the same connection times
from a shared secret and independently attempt TCP simultaneous open.
There is no coordinator, pair-selection service, or rendezvous message.

Successful connections have a separate `holepunch` connection type and
allowance. Ordinary outbound connections are unchanged. Advertisements
are unsigned and do not establish persistent node identities.

## Copyright

This BIP is licensed under the BSD-2-Clause License.

## Motivation

Nodes without publicly reachable listening ports can make ordinary
outbound connections but cannot offer the corresponding inbound capacity.
TCP hole punching can provide additional direct connections between some
of these nodes without requiring a public relay for their traffic.

The intended pace is roughly one successful additional connection per
ten minutes while the node has spare holepunch capacity. This is a soft
evaluation target, not a deadline or a guarantee. Connection attempts need
not follow block arrivals, and filling the allowance slowly is acceptable.

## Scope and draft status

Participation is optional. Only IPv4 is supported. The local endpoint used
for punching must have a sufficiently stable external mapping across
destinations. Endpoint observations provide evidence of this property,
not proof. Endpoint-independent mapping alone does not guarantee success:
filtering, early resets, socket behavior, and NAT hairpinning also matter.
See [RFC 5382](https://www.rfc-editor.org/rfc/rfc5382.html) and
[RFC 9293, section 3.5](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5).

This is an initial specification for review, not a deployable assignment.
The address network ID and authors are unassigned. The numerical timing
profile is provisional and has not been tested on real NATs. Socket
experiments, realistic gossip measurements, and test vectors remain to be
completed. The working filename's `v6` means the sixth design, not IPv6 or
the wire-format version.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" are interpreted as in RFC 2119.

### Definitions and encodings

An **endpoint** is an IPv4 address and TCP port. Different ports on the
same public IPv4 address are different endpoints. A **punch binding** is
the local IPv4 address and TCP port used for both endpoint observation
and simultaneous-open attempts. Its external port need not equal its
local port or the ordinary Bitcoin listening port.

A **round** is a fixed UTC interval used for scheduling. An **epoch** is
a longer fixed UTC interval during which an advertisement is valid. An
**attempt** includes TCP establishment, BIP 324 transport establishment,
and the Bitcoin handshake and connection proof.

All integers in serialized data are unsigned and little-endian, except
TCP ports, which are big-endian. `u32le`, `u64le`, and `u16be` denote
fixed-width encodings. `||` denotes byte concatenation. Literal strings
in cryptographic formulas are ASCII without a terminator. Hashes are raw
32-byte digest outputs; they are not reversed or hex-encoded unless
explicitly stated. `int256` interprets 32 bytes as a big-endian unsigned
integer. Division followed by `floor` uses exact integer arithmetic.

`SHA256`, `HMAC-SHA256`, and `HKDF-Extract`/`HKDF-Expand` have their usual
definitions; HKDF uses SHA256 as specified in
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

### Provisional timing profile

These values define one consistent version-0 schedule. Implementations
experimenting with this version MUST use the same schedule parameters;
independent tuning would make peers disagree about attempts. Their
suitability must be measured before deployment.

| Parameter | Value |
|-----------|-------|
| Round duration | 60 seconds |
| Epoch duration | 3,600 seconds (60 rounds) |
| Eligibility threshold | `2^251`, giving probability `1/32` per pair per round |
| Start offset within a round | From 5,000 through 34,999 milliseconds |
| TCP establishment deadline | Scheduled start plus 10 seconds |
| Complete handshake deadline | Scheduled start plus 20 seconds |
| Clock-error assumption | At most 2 seconds from UTC at each endpoint |

Epoch and round numbers are `floor(unix_time_seconds / 3600)` and
`floor(unix_time_seconds / 60)`. Unix time excludes leap seconds. Round
`r` belongs to epoch `floor(r / 60)`. These numbers do not depend on the
blockchain tip, block timestamps, or when an advertisement was received.

### Endpoint observation

An implementation MUST leave ordinary outbound connection selection,
source-port behavior, and connection allowances unchanged by this
protocol. It MAY open a small, separately budgeted set of auxiliary
connections to public IPv4 Bitcoin peers from its punch binding.
Observation connections are not completed holepunch connections and MUST
NOT consume the ordinary outbound allowance. Observers need not implement
this BIP and do not coordinate connection attempts.

The observer's `version` message supplies its view of the connection
source in `addr_recv`. Only reports on direct, nonproxied connections
made from the punch binding count. Reports with a nonglobal IPv4 address
or port zero MUST be ignored. Reports on existing connections using a
different source binding MUST NOT be used to infer the punch binding's
external port.

A node may advertise an endpoint only while at least two currently
connected observers in distinct network groups agree on it, and there
is no second such agreeing set reporting a different endpoint. Network
groups are those used locally for outbound diversity, such as IPv4 /16
groups or autonomous systems. A lone dissenting report does not invalidate
an agreeing set. This is evidence of a suitable mapping, not an assertion
that observers are honest or that all destinations see the same mapping.

If this condition stops holding, the node MUST stop originating
advertisements and starting new attempts using that endpoint. Attempts
already started may finish with their pinned inputs. If the observed
endpoint changes, subsequent attempts require an advertisement for the
new endpoint. Existing successfully authenticated connections continue.

The punch binding MUST remain fixed while its advertisement is used.
Observation and attempt sockets must be able to share that binding;
the socket options needed to do so are operating-system specific. When
the binding cannot be reused, an attempt fails or is skipped. A node MUST
NOT substitute an ephemeral source port for a holepunch attempt.

### Advertisement format

This BIP requests a new BIP 155 network ID, called `HOLEPUNCH` below. Its
numeric value is **TBD**. No existing network ID, including ordinary IPv4,
is redefined. The `addr` payload is exactly 42 bytes:

| Type | Name | Meaning |
|------|------|---------|
| `uint8` | `format` | 0 for this specification |
| `uint8[4]` | `ipv4` | IPv4 address in network byte order |
| `uint32` | `epoch` | UTC epoch number |
| `uint8[33]` | `public_key` | Compressed secp256k1 public key |

The outer `addrv2` port is the external TCP port. Its timestamp and
service bits retain their ordinary meanings as relay and service hints;
they are not inputs to scheduling or cryptographic proofs. A participating
node SHOULD advertise `NODE_P2P_V2` in its service bits.

The key MUST be a fresh ephemeral key for this endpoint and epoch, created
independently of wallet keys. Its secret scalar is uniform in `[1, n-1]`,
where `n` is the secp256k1 group order. A compressed public key consists of
`0x02` or `0x03` followed by a 32-byte big-endian x coordinate and MUST
decode to a finite point on secp256k1. Invalid keys MUST be rejected before
performing ECDH. There is no signature field or persistent identity key.

Records with an incorrect payload length, unsupported format, invalid
public key, port zero, or a non-globally-routable destination MUST NOT be
retained for use or relayed. Invalid records do not make the remaining
records in a well-formed `addrv2` message invalid. Ordinary BIP 155 message
framing rules still apply. Attempt selection MUST also respect local
destination restrictions and MUST exclude the node's own public IPv4
address; same-public-address NAT hairpinning is not attempted in this
initial profile.

### Relay, retention, and conflicts

Nodes that understand `HOLEPUNCH` use the existing `addrv2` mechanism to
originate and relay these records, including nodes that do not themselves
punch. This BIP adds no address-discovery message or relay overlay.
Ordinary relay fanout, source selection, and bandwidth policies apply.
`sendaddrv2` remains necessary to send `addrv2`, but does not imply support
for this network ID or willingness to attempt a connection.

Only records for the receiver's current epoch may be admitted or relayed.
They expire at the epoch boundary regardless of outer timestamps. There
is no preannouncement of the next epoch in this initial profile. A node
MAY evict a record earlier under its normal resource policies. Retention
for punching MUST be bounded and nonpersistent; this BIP does not require
a particular cache implementation or size.

A node MUST retain at most one active record per endpoint. Once a valid
record is admitted, a conflicting record for that endpoint MUST NOT
replace it while it remains retained. An identical record, differing only
in outer timestamp or service bits, is not a conflict and MUST NOT extend
its validity. A conflicting record MUST NOT be forwarded in place of the
retained record. After expiry or ordinary eviction, a record is considered
for admission anew. Locally owned endpoints use the node's own descriptor,
not a conflicting record received from a peer.

This is a local conflict rule, not global agreement on endpoint ownership.
Different nodes can retain different records. A forged record admitted
first can temporarily suppress the honest record. A node MUST NOT claim
that passing these checks authenticates the endpoint.

An advertiser MUST originate at most one descriptor for an endpoint in
an epoch. It MUST NOT rotate the key or change the descriptor in that
epoch while keeping the endpoint. After a restart that loses the key,
it must wait for the next epoch or obtain a different external endpoint.
Keys for a later epoch are independently generated. An authenticated
connection does not expire merely because its advertisement does.

### Pair derivation

Both nodes must possess the same two descriptors, from the same epoch,
to derive a matching schedule. Reject a pair with equal endpoints or
equal public keys. For an advertisement define:

```text
chain = SHA256(SHA256(serialized_genesis_block_header))
D = chain || addr_payload || u16be(external_port)
id = SHA256(D)
```

`addr_payload` is exactly the 42 bytes above, so `D` is 76 bytes. The
genesis header is the ordinary 80-byte Bitcoin header for the network
on which the connection is made. `chain` is the raw double-SHA256 output,
the reverse of the conventional displayed genesis block hash.

Order the two descriptors by lexicographic order of their 33-byte public
keys, giving `D_lo` and `D_hi`. The owner of `D_lo` is the BIP 324
initiator and the owner of `D_hi` is the responder, independently of
whether the operating system returns the socket through `connect()` or
`accept()`.

Let `d` be the local secret scalar and `Q` the decoded peer public key:

```text
Z = big_endian_32_bytes(x_coordinate(d * Q))
salt = SHA256("BitcoinHolePunch/v0" || D_lo || D_hi)
PRK = HKDF-Extract(salt, Z)
K_schedule = HKDF-Expand(PRK, "schedule", 32)
K_auth = HKDF-Expand(PRK, "authentication", 32)
```

`Z` is the raw x coordinate, not a library-specific hash of the ECDH
point. The two parties derive the same `Z`, descriptors, and keys.
Neither a block anchor nor a signature is part of the derivation.

### Scheduling

For a current or future round `r` belonging to the descriptors' epoch,
compute:

```text
draw = int256(HMAC-SHA256(K_schedule, "eligibility" || u64le(r)))
eligible = draw < 2^251
U = int256(HMAC-SHA256(K_schedule, "time" || u64le(r)))
offset_ms = 5000 + floor(U * 30000 / 2^256)
start_ms = 60000 * r + offset_ms
priority = HMAC-SHA256(K_schedule, "priority" || u64le(r))
```

Eligibility is determined independently for each pair. A node MUST NOT
change the threshold according to its cache size or make eligibility
depend on the pair's ranking among unrelated candidates. Knowledge of a
third node does not change the pair's eligibility or start time.

Local resource limits MAY cause a node to skip an otherwise eligible
attempt. A node that is full MUST NOT start further attempts. If a local
policy ranks eligible pairs for a round, lower big-endian `priority`
values rank first, with `D_lo || D_hi` as the tie-breaker. Each node may
still select different pairs because its knowledge and capacity differ.
A skipped attempt MUST NOT be moved to another time in the round.

Only attempts whose scheduled start is still in the future when both
records become available may be scheduled. At attempt start the node
MUST recheck record validity, observer agreement, and available capacity,
then pin both descriptors, `r`, the transport role, and derived keys.
Eviction or later gossip MUST NOT change these pinned values.

Use UTC to compute the schedule and monotonic timers to execute it. A
detected wall-clock discontinuity MUST cancel uncompleted scheduled and
active attempts; only future opportunities may then be scheduled. Nodes
whose clocks do not meet the profile's assumption may fail to connect.
This BIP does not obtain time from peer timestamps or block arrival times.

### TCP establishment

At the scheduled start both parties actively open TCP from their punch
bindings to the advertised peer endpoint. Attempts MUST be nonblocking.
There MUST be at most one attempt or established holepunch connection for
a given local/remote endpoint tuple, regardless of advertisement key.

An attempt's TCP deadline is its scheduled start plus 10 seconds. A failed
connect MAY be retried at the scheduled start plus 2, 4, 6, or 8 seconds,
provided its previous socket has been closed. A pending connect MUST NOT
be replaced simply because one of these retry times arrives. Kernel TCP
retransmissions are permitted within the deadline. There is no locally
shifted retry schedule; further opportunities use future shared rounds.

An implementation MAY listen on the punch binding if its operating system
supports simultaneous listening and connecting there. An accepted socket
may satisfy an attempt only if its local/remote endpoint tuple matches a
pending attempt and it arrives before that attempt's TCP deadline. All
other accepted sockets MUST be closed. If both paths produce sockets,
keep only the first locally selected socket and close the others; the
attempt may fail if the parties select different connections.

After selecting a socket, close any superseded attempt socket and begin
BIP 324 using the pinned role. Fresh BIP 324 transport keys MUST be used;
advertisement keys MUST NOT be used as transport keys. There is no v1
fallback on this connection. TCP failures, resets, mapping changes,
`TIME_WAIT`, or unsupported socket operations may cause an attempt to
fail. They do not justify substituting another source port or endpoint.

### Handshake and connection proof

After BIP 324 transport establishment, its initiator sends the Bitcoin
`version` message first. The responder replies with its own `version`.
Accounting as `holepunch` does not change these roles.

Each side then sends a BIP 434 `feature` message after receiving the
peer's `version` and before sending its own `verack`. Neither side waits
for the other's proof before sending its own proof and `verack`. BIP 434's
protocol-version requirements apply; an incompatible peer fails the
attempt.

Until a BIP number is assigned, `featureid` is the 64-character lowercase
hex encoding of `SHA256("BitcoinHolePunch/v0/feature")`. This identifier
is distinct from the earlier coordinator-based proposal. `featuredata`
is exactly 105 bytes:

| Type | Name | Meaning |
|------|------|---------|
| `uint8` | `format` | 0 |
| `uint64` | `round` | The pinned attempt round |
| `uint8[32]` | `sender_id` | Sender's pinned descriptor ID |
| `uint8[32]` | `receiver_id` | Receiver's pinned descriptor ID |
| `uint8[32]` | `proof` | The MAC defined below |

Let `role` be one byte, 0 for the sender being the BIP 324 initiator and
1 for the sender being the responder. The proof is:

```text
proof = HMAC-SHA256(K_auth,
    "connection" || bip324_session_id || u64le(round) ||
    sender_id || receiver_id || role)
```

Each node MUST check the exact length, format, round, descriptor IDs, and
proof against its pinned attempt. The peer's role is inferred from the
pinned descriptors. The proof MUST be compared in constant time. A
missing proof at receipt of `verack`, duplicate proof feature, malformed
proof feature, or failed proof MUST terminate the attempt.

The local Bitcoin handshake and peer proof check must complete by the
scheduled start plus 20 seconds. Until then the peer is pending and MUST
NOT be admitted for ordinary transaction or block relay. Completion requires
sending the local proof and `verack`, and receiving and validating the
peer's proof and `verack`. No additional acknowledgement message is used.

The proof establishes continuity with the advertised ephemeral key and
binds it to this encrypted session. It does not establish a real-world
identity, authenticate the gossip source, or prove endpoint ownership
before sending TCP packets.

### Connection accounting and lifecycle

Successfully completed attempts are `holepunch` connections at both ends.
They use a separate local allowance and MUST NOT count as ordinary
outbound peers or displace peers protected by ordinary outbound selection.
Observation connections and pending attempts also require separately
budgeted resources; they are not successful holepunch connections.

An authenticated holepunch connection may perform normal Bitcoin peer
services subject to the implementation's ordinary service and relay
policies. The allowance size and replacement policy are local choices.
The allowance MUST NOT be exceeded. Once full, a node cancels remaining
attempts and stops starting new ones until capacity is available.
Nodes MAY continue to relay advertisements while full; an advertisement
does not promise that its owner has a free slot.

Close unfinished sockets at their deadlines and release the attempt
state. Established authenticated connections survive advertisement expiry,
cache eviction, or loss of endpoint observations. Descriptor secrets and
derived keys should be erased when no longer needed for valid attempts;
they are unnecessary for an already admitted connection's transport.

The timing profile ends every unfinished attempt before local round
second 55. The next round's earliest start is second 5. With both clocks
within two seconds of UTC, adjacent rounds have a gap of more than six
seconds between these bounds. Epoch boundaries coincide with round
boundaries, so old and new epoch attempts do not overlap under these
assumptions. This guard does not eliminate kernel `TIME_WAIT` constraints.

## Rationale

### Independent pair eligibility

If A selects B as its favorite candidate, B may select C instead. A shared
ranking therefore does not establish a matching. Here A and B compute a
shared random draw for their own pair. If it qualifies, knowledge of C
does not change that decision. Missing advertisements and local capacity
limits can still prevent reciprocal attempts.

Under the illustrative model where each of `N` nodes independently retains
`m` uniform distinct peers, the expected number of mutually known peers
is `m^2 / (N-1)`. For `N = 10,000`, `m = 256`, and the provisional
threshold, there are about 2.05 mutually eligible opportunities per node
per ten minutes before gossip expiry, capacity skips, and TCP failures.
This motivates an experiment, not a claimed connection success rate.
The [discovery model](bip-holepunch-v6/plot_mutual_discovery.py) and
[plot](bip-holepunch-v6/mutual-discovery.png) describe the snapshot
assumptions; they do not simulate this protocol.

### Existing connections and discovery

Sharing a port across all existing outbound connections could provide
observations of that port's mapping, but would change their socket
behavior. Auxiliary observations preserve the existing outbound system.
They use normal Bitcoin peers rather than a new discovery service.

Using `addrv2` reuses the existing dissemination mechanism. It does not
make older nodes understand the new type. Sparse adoption may provide
poor propagation and low reciprocal visibility. No special topology or
feature-capable peer-selection mechanism is specified here.

### Short-lived unsigned records

Ephemeral keys provide a shared secret without persistent node identities
or wallet involvement. Self-signatures would not establish ownership of
the advertised address. This draft omits them and accepts that records
can be forged or modified.

An endpoint includes its port so that distinct nodes behind the same
public IPv4 address can be advertised separately. Retaining the first
admitted record limits replacement churn but permits temporary squatting
by forged records. Short epochs bound record lifetime. Current-epoch-only
admission avoids overlapping keys for new attempts, at the cost of gossip
warm-up after every epoch and possible delay after a restart.

### Time and block hashes

The ten-minute connection target does not require block-driven scheduling.
UTC rounds provide shared windows even when nodes have different chain
tips. Omitting block anchors removes anchor validation, reorg, and IBD
rules. A known block hash would not prevent an attacker from grinding
advertisement fields for favorable schedules.

## Backward compatibility

Nodes that do not implement this BIP keep their existing connection and
address-relay behavior. Under BIP 155, unknown address network IDs should
not be relayed. This protocol therefore needs paths through nodes that
understand `HOLEPUNCH`; `sendaddrv2` by itself is insufficient evidence.

No legacy `addr` encoding is defined for these records. No ordinary IPv4
address encoding, service bit, or connection type is reinterpreted. This
draft does not implement the earlier coordinator proposal's wire format,
messages, or fallback behavior.

## Security and privacy considerations

**False addresses and SYN abuse.** Advertisements do not prove endpoint
ownership. An attacker can advertise a victim's address and induce
participants to send TCP packets to it. Even a successful connection proof
occurs after those packets have been sent. Local resource policies can
limit a participant's contribution but do not bound aggregate traffic to
a victim from the entire network. A network-wide mitigation is not
specified by this BIP. Implementations need to evaluate this risk before
deployment. Counting connect calls alone omits kernel retransmissions.

**Sybil influence and grinding.** An attacker knows the shared secrets for
pairs involving its own keys and can vary keys or other descriptor fields
to obtain favorable eligibility, timing, or priority. The threshold is not
proof of work or a Sybil defense. An IP:port uniqueness rule is not an
operator-uniqueness rule. Cache admission, source diversity, CPU budgets,
and destination cooldowns are local policies; they should not rely on
advertised identities or assume changing a key makes a new destination.

**Conflicting records.** Unsigned gossip can poison an endpoint's retained
record, cause mismatched schedules, or cause connection proofs to fail.
The first-admitted rule offers no authoritative way to identify the honest
record. Ordinary outbound diversity remains independent of this pool.

**Observers and clocks.** Colluding observers can report a false mapping;
network-group agreement is not authentication. Stale mappings, lost
observers, and clock errors reduce connectivity. Peer-supplied time is not
a substitute for the profile's clock assumption.

**Endpoint exposure.** Publishing an advertisement exposes the address
and port of a previously unreachable node. Key rotation does not unlink
a stable endpoint. Shared schedules are hidden from passive observers
without either private key, but participating attackers know schedules
for their own pairs. No anonymity guarantee is made.

## Reference implementation

No implementation of this protocol is provided yet. The existing
coordinator-based implementation material is not an implementation of
this design. Shared-port behavior, simultaneous-open support, clock skew,
and NAT traversal need experiments on the intended operating systems and
network devices before the timing profile can be recommended.

## Test vectors

Test vectors have not yet been provided. They must cover advertisement
serialization and rejection, secp256k1 key validation, symmetric ECDH and
KDF derivation, eligibility and offset boundaries, transport roles, and
session-bound proofs. Lifecycle cases must include epoch transitions,
conflicting records, opposite clock errors, late gossip, local capacity
skips, missing proofs, and established connections surviving expiry.

## Open items

- Fill in author details and obtain an address network ID and BIP number.
- Validate or revise the provisional timing and eligibility profile using
  realistic gossip and socket/NAT experiments, including epoch warm-up.
- Review the first-admitted conflict rule and its suppression tradeoff.
- Confirm practical observation, cache, and extra-connection budgets.
- Produce interoperable implementations and test vectors.

## Changelog

- 0.1.0: Initial coordinatorless IPv4 draft.
