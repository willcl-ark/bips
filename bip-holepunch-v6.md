```
  BIP: ?
  Layer: Peer Services
  Title: Coordinatorless IPv4 TCP Hole Punching
  Authors:
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Version: 0.3.0
  Requires: 155, 324, 434
```

## Abstract

This document specifies additional Bitcoin peer connections between IPv4
nodes behind compatible NATs or stateful firewalls. Nodes gossip an
external endpoint and an ephemeral public key through `addrv2`. Two nodes
that retain each other's advertisements derive shared eligibility and
priority from their public IPv4 addresses, and connection times from a
shared secret, then independently attempt TCP simultaneous open.
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

This draft defines a version-1 profile for interoperable experiments.
The proposed address network ID is not an approved assignment. Author
details and a BIP number remain to be supplied. The timing profile and
recommended local budgets are concrete starting points, not measured NAT
or gossip performance. Public deployment still requires socket/NAT and
reciprocal-discovery measurements. The working filename's `v6` means the
sixth design, not IPv6 or the wire-format version.

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

### Version-1 timing profile

Implementations of this version MUST use these schedule parameters;
independent tuning would make peers disagree about attempts. Changing
them requires a new incompatible format and cryptographic domain. Their
suitability must be measured before deployment.

| Parameter | Value |
|-----------|-------|
| Round duration | 60 seconds |
| Epoch duration | 3,600 seconds (60 rounds) |
| Eligibility threshold | `2^251`, giving probability `1/32` per IPv4 pair per round |
| Start offset within a round | From 5,000 through 34,999 milliseconds |
| TCP establishment deadline | Scheduled start plus 10 seconds |
| Complete handshake deadline | Scheduled start plus 20 seconds |
| Clock-error assumption | At most 2 seconds from UTC at each endpoint |
| Earliest origination in an epoch | Local epoch start plus 5 seconds |

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

This BIP proposes BIP 155 network ID `0x08`, called `HOLEPUNCH` below.
Experiments with this draft use that value on isolated test networks;
public use requires its reservation through the BIP process. This proposal
does not establish an assignment. No existing network ID, including
ordinary IPv4, is redefined. The `addr` payload is exactly 42 bytes:

| Type | Name | Meaning |
|------|------|---------|
| `uint8` | `format` | 1 for this specification |
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

An advertiser SHOULD enqueue its current descriptor when observer
agreement is established or restored, at each new epoch, and after a new
address-relay peer completes its handshake and has sent `sendaddrv2`.
Origination MUST wait until at least five seconds after the local epoch
boundary, including on startup. This guard prevents a fast clock's new
descriptor from reaching a compliant slow clock in its previous epoch.
Origination uses the ordinary address send queue but MUST NOT depend on
the ordinary local-address rebroadcast interval or on public listening
reachability. Per-peer duplicate suppression still applies.
Unsolicited messages carrying these records for onward relay SHOULD
contain at most ten address records in total. Existing Bitcoin Core
relay policy does not forward addresses from larger batches. Split queued
announcements across ordinary send opportunities without bypassing rate
limits; bulk `getaddr` responses retain their ordinary limits.

Duplicate suppression MUST distinguish descriptors, including their epoch
and key; the descriptor ID defined below is suitable. Endpoint-only
suppression would hide the next epoch's record. At transmission time,
discard expired or no-longer-retained records and recheck observer
agreement for locally originated records. Relay queues and cached
`getaddr` responses must not bypass these checks. Implementations MAY
include retained records in ordinary `getaddr` responses within the
existing combined message limits and response policies.

Only records for the receiver's current epoch may be admitted or relayed.
They expire at the epoch boundary regardless of outer timestamps. There
is no preannouncement of the next epoch in this initial profile. A node
MAY evict a record earlier under its normal resource policies. Retention
for punching MUST be bounded and nonpersistent; this BIP does not require
a particular cache implementation or size.

Keep this cache separate from ordinary dialable addresses. A `HOLEPUNCH`
record MUST NOT enter ordinary outbound, feeler, or anchor selection, or
be converted to an ordinary IPv4 record. A successful punched connection
MUST NOT mark its endpoint as publicly reachable in the ordinary address
manager. Its reachability depended on a scheduled attempt.

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
Loss and recovery of observer agreement in the same epoch does not
permit a new descriptor for the same endpoint. If an endpoint changes
away and returns, reuse its original descriptor and key or wait for the
next epoch.

### Pair derivation

Both nodes must possess the same two descriptors, from the same epoch,
to derive matching connection times and proofs. Reject a pair with equal
public IPv4 addresses or equal public keys. For an advertisement define:

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
salt = SHA256("BitcoinHolePunch/v1" || D_lo || D_hi)
PRK = HKDF-Extract(salt, Z)
K_schedule = HKDF-Expand(PRK, "schedule", 32)
K_auth = HKDF-Expand(PRK, "authentication", 32)
```

`Z` is the raw x coordinate, not a library-specific hash of the ECDH
point. The two parties derive the same `Z`, descriptors, and keys.
Neither a block anchor nor a signature is part of the derivation.

### Scheduling

Order the two four-byte public IPv4 addresses lexicographically, giving
`IP_lo` and `IP_hi`. This ordering is independent of the public-key
ordering used for transport roles. For a current or future round `r`
belonging to the descriptors' epoch, compute:

```text
S = chain || u64le(r) || IP_lo || IP_hi
draw = int256(SHA256("BitcoinHolePunch/v1/eligibility" || S))
eligible = draw < 2^251
priority = SHA256("BitcoinHolePunch/v1/priority" || S)
U = int256(HMAC-SHA256(K_schedule, "time" || u64le(r)))
offset_ms = 5000 + floor(U * 30000 / 2^256)
start_ms = 60000 * r + offset_ms
```

`S` is 48 bytes. Eligibility and priority are public and identical for
all descriptors using the same pair of IPv4 addresses in a round.
Changing a key or port cannot improve either value. The exact start
time remains specific to the descriptor pair and its shared secret.

Eligibility is determined independently for each IPv4 pair. A node MUST
NOT change the threshold according to its cache size or make eligibility
depend on ranking among unrelated candidates. Knowledge of a third node
does not change a pair's eligibility or start time.

Local resource limits MAY cause a node to skip an otherwise eligible
attempt. A node that is full MUST NOT start further attempts. Group
candidates by remote IPv4 address before selection. A node MUST NOT start
more than one new attempt per remote IPv4 address in a round, across all
ports and keys. The scheduled retries of that
attempt do not create another allocation. This is a resource grouping,
not a rule that one retained descriptor replaces other endpoints at that
IP. The endpoint-specific conflict rule still applies.

If a local policy ranks eligible IPv4 groups, lower big-endian `priority`
values rank first, with `IP_lo || IP_hi` as the tie-breaker. Within a
selected group, it is RECOMMENDED to prefer the endpoint pair with the
lowest big-endian `endpoint_priority`, defined as follows. Encode each
endpoint as `ipv4 || u16be(port)` and order these six-byte encodings
lexicographically as `E_lo` and `E_hi`:

```text
endpoint_priority = SHA256("BitcoinHolePunch/v1/endpoint" ||
    chain || u64le(r) || E_lo || E_hi)
```

Use `E_lo || E_hi` to break ties. This preference varies by round without
depending on keys. It MUST NOT affect the group's eligibility, priority,
or number of allocations. Each node may still select different endpoint
pairs because its retained records and capacity differ. A skipped attempt
MUST NOT be moved to another time in the round.

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
hex encoding of `SHA256("BitcoinHolePunch/v1/feature")`. This identifier
is distinct from the earlier coordinator-based proposal. `featuredata`
is exactly 105 bytes:

| Type | Name | Meaning |
|------|------|---------|
| `uint8` | `format` | 1 |
| `uint64` | `round` | The pinned attempt round |
| `uint8[32]` | `sender_id` | Sender's pinned descriptor ID |
| `uint8[32]` | `receiver_id` | Receiver's pinned descriptor ID |
| `uint8[32]` | `proof` | The MAC defined below |

The experimental `featureid` is
`a3f13a7f6c39ee3c031aa28cffd55bc3cdbf7be05e5c0a0264c6b277af0346bc`.
The BIP 434 payload is `0x40 || ASCII(featureid) || 0x69 || featuredata`,
where `0x40` and `0x69` are the CompactSize lengths. BIP 434's BIP 324
message type is 37. Both advertised protocol versions MUST be at least
70017. The `bip324_session_id` below is the raw 32-byte BIP 324 session ID.

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

### Recommended experimental local policy

The following defaults make an initial implementation concrete. Their
numerical budgets are recommendations, not protocol requirements or
additional inputs to pair derivation. Implementations MAY choose higher
or lower budgets; differing budgets can cause otherwise eligible attempts
to be skipped. These defaults have not been validated as production
operating limits.

| Resource | Initial default |
|----------|-----------------|
| Retained remote descriptors | 1,024, excluding the locally owned descriptor |
| Observation connections | 3 steady connections in distinct network groups; at most 4 during replacement |
| Observation refresh | Replace the oldest observer every 10 minutes; stop counting a report after 30 minutes |
| New pair attempts | At most 4 per round |
| Concurrent pending attempts | At most 4 |
| Established holepunch allowance | 4 |

Observation age is measured with a monotonic clock from receipt of the
observer's `version`. Obtain a fresh report by connecting to a replacement
observer from the same punch binding; a `ping` response does not update
the reported mapping.
Keep the old connection until its replacement completes the handshake,
subject to the freshness and connection bounds. A failed replacement
does not extend the old report's lifetime. Select observers using ordinary
outbound destination restrictions and network-group diversity. These
auxiliary connections consume additional resources at the public peers
as well as locally.

At each round boundary, take the currently retained valid candidates,
excluding endpoint tuples with an existing connection or pending attempt.
Group them by remote IPv4 address and select eligible groups in the
specified priority order up to the configured per-round attempt budget.
Choose one endpoint pair per selected group using `endpoint_priority`.
Advertisements arriving later wait for the next round. Execute only those
selections at their derived starts, with the required validity and capacity
rechecks. Do not backfill skipped selections, including with another
endpoint at the same IP. Each selected pair has at most the initial connect
and four scheduled retries. With the recommended four-attempt budget this
bounds application connect calls to 20 per round, not the number of SYN
packets.

Keep healthy established connections until ordinary peer policy
disconnects them; do not replace one just to admit a new candidate. Check
capacity again before admitting a completed handshake. Address input,
relay, cache admission, and ECDH work need bounded queues and local
budgets. Reuse ordinary per-source address processing limits and private
randomized cache admission/eviction, rather than using the public pair
priority to decide cache admission. None of these defaults resolves the
network-wide induced-SYN risk described below.

## Rationale

### Independent pair eligibility

If A selects B as its favorite candidate, B may select C instead. A shared
ranking therefore does not establish a matching. Here A and B compute a
shared draw for their public IPv4 pair. If it qualifies, knowledge of C
does not change that decision. Shared priorities also preserve correlation
between the two nodes' selections when their budgets are limited. Missing
advertisements and local capacity limits can still prevent reciprocal
attempts. Endpoints sharing a public IP share one allocation; their
endpoint preferences need not produce reciprocal choices from different
retained sets.

Under the illustrative model where each of `N` nodes independently retains
`m` uniform distinct peers, each on a distinct public IP, the expected
number of mutually known peers is `m^2 / (N-1)`. For `N = 10,000`,
`m = 256`, and the version-1 threshold, there are about 2.05 mutually
eligible opportunities per node
per ten minutes before gossip expiry, capacity skips, and TCP failures.
This also requires an average of eight locally eligible attempts per
minute: most candidates do not retain the local advertisement. A smaller
attempt budget reduces reciprocal attempts even with shared priorities.
The recommended 1,024-entry cache and four-attempt cap trade additional
retention for fewer connection attempts; the uncapped example is not a
prediction for those defaults.
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

The first-admitted rule is retained for version 1: unsigned competing
records provide no basis to prefer a replacement. Last-received-wins
would instead allow continuous schedule disruption. Experiments should
measure honest-record suppression, but the conflict rule is not left to
implementation choice.

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

Format 1 replaces the earlier experimental format 0. Implementations of
this profile MUST reject format-0 advertisements and proofs; there is no
fallback. The new cryptographic domain and feature identifier separate
the incompatible scheduling rules.

## Security and privacy considerations

**False addresses and SYN abuse.** Advertisements do not prove endpoint
ownership. An attacker can advertise a victim's address and induce
participants to send TCP packets to it. Even a successful connection proof
occurs after those packets have been sent. Local resource policies can
limit a participant's contribution but do not bound aggregate traffic to
a victim from the entire network. A network-wide mitigation is not
specified by this BIP. Implementations need to evaluate this risk before
deployment. Counting connect calls alone omits kernel retransmissions.

**Sybil influence and grinding.** For a fixed pair of public IPv4 addresses,
keys and ports cannot change eligibility or group priority. An attacker
can still search invented IP addresses for favorable draws without
controlling those addresses. It can also grind ports for preference within
one IP's allocation, or keys and ports for an exact start time. Neither
the public lottery nor the per-IP allocation establishes an operator
identity or makes false address claims costly. Cache admission, source
diversity, CPU budgets, and destination cooldowns remain necessary.

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
a stable endpoint. Eligibility, group priority, and endpoint preference
are public. Only exact connection times remain hidden from passive
observers without either private key; participating attackers can derive
those times for their own pairs. No anonymity guarantee is made.

## Reference implementation

The [Python reference](bip-holepunch-v6/reference.py) implements encoding,
pair derivation, scheduling, and connection-proof formulas. It reuses the
BIP 324 reference's secp256k1 arithmetic and is test-only, not constant-time
or suitable for production secrets. Its IPv4 checks are illustrative;
implementations must also apply their ordinary destination restrictions.

No networking implementation of this design is provided yet. The existing
coordinator-based implementation material is not an implementation of it.
Shared-port behavior, simultaneous-open support, clock skew, and NAT
traversal need experiments on the intended operating systems and devices
before public deployment.

## Test vectors

The [vectors](bip-holepunch-v6/test-vectors.json) contain fixed inputs and
expected hexadecimal bytes for advertisements, descriptors, ECDH/KDF,
schedule draws, and both directions of the session-bound proof. They
include a shared x coordinate with a leading zero, both transport roles,
invalid compressed keys, and exact eligibility and offset boundaries.
Tests also check that changing keys or ports preserves the public-IP
lottery, that both sides agree on all schedule values, and that exact
times and connection proofs remain bound to the descriptors.
The sample public endpoints are serialization inputs only; the tests do
not contact them. The experimental network ID is an explicit input.

Run `python3 bip-holepunch-v6/test_vectors.py` to verify the frozen vectors,
both sides' derivations, and malformed records and proofs. Regeneration
requires the explicit `--generate` argument. These tests do not exercise
sockets or the lifecycle. A networking implementation must additionally
check at least the following cases:

| Case | Required outcome |
|------|------------------|
| Clocks at +2 and -2 seconds; origination at local epoch second 5 | Both receivers are in the new epoch |
| Queued advertisement crosses expiry | Discard before sending |
| Same endpoint advertises a new epoch/key | Old descriptor does not suppress the new announcement |
| Conflicting key for a retained endpoint in the same epoch | Keep the first descriptor |
| Several retained endpoints share a remote public IP | Keep distinct endpoint records; select at most one attempt for the IP per round |
| A selected endpoint becomes unusable before its start | Skip without backfilling another endpoint at that IP |
| Observer agreement is lost and restored | No intervening new attempts; reuse the original descriptor |
| Gossip arrives after the scheduled start | Wait for a future opportunity |
| Capacity fills while other handshakes are pending | Admit no more than the allowance; cancel remaining attempts |
| Record is evicted after attempt start | Keep the attempt's pinned inputs |
| A retry time arrives while connect is pending | Keep that socket and binding |
| Missing, duplicate, or invalid proof before peer admission | Terminate the attempt |
| Established connection outlives the epoch or observers | Keep the connection under ordinary peer policy |

## Assignment and deployment work

Author details, a BIP number, and reservation of the proposed address
network ID remain administrative work. The version-1 wire profile,
first-admitted conflict rule, and experimental local defaults above are
the recommended starting point for implementation.

Before public deployment, demonstrate interoperability between independent
implementations and measure socket reuse and NAT traversal under clock
skew, loss, resets, and mapping changes. Measure reciprocal advertisement
visibility over each epoch, including time to rebuild caches, sparse
adoption, conflicting records, and adversarial admission. Record actual
SYN traffic as well as application attempts, observer load, and successful
additional connections. The ten-minute target is evaluated after these
losses; the snapshot discovery model alone cannot establish it. Failure
to meet that target is grounds to revisit the profile, not to tune shared
parameters independently.

## Changelog

- 0.3.0: Replace format 0 with an IP-pair eligibility and priority lottery;
  retain shared endpoint selection, ECDH-derived times, and local budgets.
- 0.2.0: Specify epoch-aware origination, experimental assignments and local
  defaults.
- 0.1.1: Add cryptographic reference code and conformance vectors.
- 0.1.0: Initial coordinatorless IPv4 draft.
