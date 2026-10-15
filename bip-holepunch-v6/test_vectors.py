"""Verify frozen vectors with `python3 test_vectors.py` (no network or writes).

Regenerate deliberately with `python3 test_vectors.py --generate`.
Private scalars and example public endpoints below are test inputs only.
"""

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.dont_write_bytecode = True
import reference as r

VECTOR_PATH = Path(__file__).with_name("test-vectors.json")
HEADER = bytes.fromhex("01000000" + "00" * 32
                       + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
                       + "29ab5f49ffff001d1dac2b7c")
CHAIN = r.sha256(r.sha256(HEADER))
EPOCH = 480000
SESSION = bytes(range(32))
CASES = ((3, 51, (0, 3, 59)), (2, r.ec.GE.ORDER - 1, (0, 34, 59)))
INVALID_KEYS = {
    "short": r.public_key(1)[:-1], "long": r.public_key(1) + b"\x00",
    "unsupported_prefix": b"\x04" + r.public_key(1)[1:],
    "not_on_curve": b"\x02" + bytes(32),
    "x_at_p": b"\x02" + r.ec.FE.SIZE.to_bytes(32, "big"),
    "x_above_p": b"\x03" + (r.ec.FE.SIZE + 1).to_bytes(32, "big"),
    "x_maximum": b"\x02" + b"\xff" * 32,
}


def descriptors(a, b):
    return tuple(r.Descriptor(CHAIN, r.advertisement(ip, EPOCH, r.public_key(d)), port)
                 for d, ip, port in ((a, "1.1.1.1", 8333), (b, "8.8.8.8", 18444)))


def build_vectors():
    pairs = []
    for a, b, rounds in CASES:
        local, peer = descriptors(a, b)
        keys, role = r.pair_keys(a, local, peer)
        number = EPOCH * 60 + rounds[1]
        proofs = [r.feature_data(keys["auth"], SESSION, number, sender, receiver, side)
                  for sender, receiver, side in ((local, peer, role), (peer, local, 1 - role))]
        pairs.append({
            "secrets": [f"{a:064x}", f"{b:064x}"],
            "descriptors": [{"ipv4": ip, "port": item.port, "public_key": item.key.hex(),
                             "addr_payload": item.payload.hex(), "D": item.encoded.hex(),
                             "id": item.id.hex(),
                             "addrv2": r.addrv2(item, EPOCH * 3600, 2048, 8).hex()}
                            for item, ip in ((local, "1.1.1.1"), (peer, "8.8.8.8"))],
            "roles": [role, 1 - role],
            "keys": {key: value.hex() for key, value in keys.items()},
            "rounds": [{"round": EPOCH * 60 + i,
                        **r.schedule(keys["schedule"], local, peer, EPOCH * 60 + i)}
                       for i in rounds],
            "proof_round": number, "featuredata": [data.hex() for data in proofs],
            "feature_payloads": [r.feature_payload(data).hex() for data in proofs],
        })
    time_boundary = (2**256 + 29999) // 30000
    return {
        "note": "Test-only. network_id 0x08 is a proposed experimental input, not an assignment.",
        "genesis_header": HEADER.hex(), "chain": CHAIN.hex(), "epoch": EPOCH,
        "network_id": 8, "services": 2048, "timestamp": EPOCH * 3600,
        "session_id": SESSION.hex(), "feature_id": r.FEATURE_ID.decode("ascii"),
        "pairs": pairs,
        "invalid_keys": {name: key.hex() for name, key in INVALID_KEYS.items()},
        "eligibility_boundaries": [{"draw": f"{n:064x}", "eligible": result}
                                   for n, result in ((0, True), (2**251 - 1, True),
                                                     (2**251, False), (2**256 - 1, False))],
        "offset_boundaries": [{"time_draw": f"{n:064x}", "offset_ms": result}
                              for n, result in ((0, 5000), (time_boundary - 1, 5000),
                                                (time_boundary, 5001), (2**256 - 1, 34999))],
    }


class TestVectors(unittest.TestCase):
    def test_frozen_vectors(self):
        vectors = json.loads(VECTOR_PATH.read_text())
        self.assertEqual(build_vectors(), vectors)
        for pair in vectors["pairs"]:
            self.assertEqual({item["eligible"] for item in pair["rounds"]}, {False, True})

    def test_keys_roles_and_symmetry(self):
        for a, b, _ in CASES:
            local, peer = descriptors(a, b)
            keys, role = r.pair_keys(a, local, peer)
            reverse, reverse_role = r.pair_keys(b, peer, local)
            self.assertEqual(keys, reverse)
            self.assertEqual(role, 1 - reverse_role)
            self.assertEqual(role, int(local.key > peer.key))
            for number in range(EPOCH * 60, (EPOCH + 1) * 60):
                self.assertEqual(r.schedule(keys["schedule"], local, peer, number),
                                 r.schedule(reverse["schedule"], peer, local, number))
            for item in (local, peer):
                self.assertEqual(int(r.decode_key(item.key).y) & 1, item.key[0] & 1)
            for name, info in (("schedule", b"schedule"), ("auth", b"authentication")):
                self.assertEqual(keys[name], r.ec.hkdf_sha256(32, keys["z"], keys["salt"], info))
        keys, _ = r.pair_keys(3, *descriptors(3, 51))
        self.assertEqual(len(keys["z"]), 32)
        self.assertEqual(keys["z"][0], 0)
        for name, key in INVALID_KEYS.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                r.decode_key(key)
        for secret in (0, r.ec.GE.ORDER):
            with self.assertRaises(ValueError):
                r.public_key(secret)

    def test_descriptor_and_pair_rejection(self):
        local, peer = descriptors(3, 51)
        bad_payloads = [local.payload[:-1], local.payload + b"\x00",
                        b"\x00" + local.payload[1:], b"\x02" + local.payload[1:]]
        bad_payloads += [local.payload[:9] + key for key in INVALID_KEYS.values()]
        bad_payloads += [b"\x01" + bytes(ip) + local.payload[5:]
                         for ip in ((0, 0, 0, 0), (127, 0, 0, 1), (10, 1, 1, 1), (224, 0, 0, 1))]
        for payload in bad_payloads:
            with self.assertRaises(ValueError):
                replace(local, payload=payload)
        for port in (0, 65536):
            with self.assertRaises(ValueError):
                replace(local, port=port)
        for invalid in (local, replace(peer, payload=peer.payload[:9] + local.key),
                        replace(peer, payload=peer.payload[:1] + local.payload[1:5] + peer.payload[5:],
                                port=local.port),
                        replace(peer, payload=peer.payload[:1] + local.ipv4 + peer.payload[5:]),
                        replace(peer, chain=bytes(32)),
                        replace(peer, payload=peer.payload[:5] + (EPOCH + 1).to_bytes(4, "little")
                                + peer.payload[9:])):
            with self.assertRaises(ValueError):
                r.pair_keys(3, local, invalid)
        with self.assertRaises(ValueError):
            r.pair_keys(4, local, peer)

    def test_boundaries(self):
        local, peer = descriptors(3, 51)
        vectors = json.loads(VECTOR_PATH.read_text())
        for case in vectors["eligibility_boundaries"]:
            self.assertEqual(r.eligible(bytes.fromhex(case["draw"])), case["eligible"])
        for case in vectors["offset_boundaries"]:
            self.assertEqual(r.offset(bytes.fromhex(case["time_draw"])), case["offset_ms"])
        for number in (EPOCH * 60 - 1, (EPOCH + 1) * 60):
            with self.assertRaises(ValueError):
                r.schedule(bytes(32), local, peer, number)
        for invalid in (replace(peer, chain=bytes(32)),
                        replace(peer, payload=peer.payload[:5] + (EPOCH + 1).to_bytes(4, "little")
                                + peer.payload[9:]),
                        replace(peer, payload=peer.payload[:1] + local.ipv4 + peer.payload[5:])):
            with self.assertRaises(ValueError):
                r.schedule(bytes(32), local, invalid, EPOCH * 60)

    def test_selection_ignores_keys_and_ports(self):
        local, peer = descriptors(3, 51)
        keys, _ = r.pair_keys(3, local, peer)
        for secret, left, right in (
                (3, replace(local, port=local.port + 1), peer),
                (3, local, replace(peer, port=peer.port + 1)),
                (52, replace(local, payload=local.payload[:9] + r.public_key(52)), peer),
                (3, local, replace(peer, payload=peer.payload[:9] + r.public_key(52)))):
            with self.subTest(local=left, peer=right):
                alternate, _ = r.pair_keys(secret, left, right)
                self.assertNotEqual(alternate["auth"], keys["auth"])
                for number in range(EPOCH * 60, (EPOCH + 1) * 60):
                    expected = r.schedule(keys["schedule"], local, peer, number)
                    actual = r.schedule(alternate["schedule"], left, right, number)
                    for field in ("draw", "eligible", "priority"):
                        self.assertEqual(actual[field], expected[field])
                    if left.port == local.port and right.port == peer.port:
                        self.assertEqual(actual["endpoint_priority"], expected["endpoint_priority"])
                    else:
                        self.assertNotEqual(actual["endpoint_priority"], expected["endpoint_priority"])
                    self.assertNotEqual(actual["time_draw"], expected["time_draw"])

    def test_public_selection_context(self):
        local, peer = descriptors(3, 51)
        number = EPOCH * 60
        baseline = r.schedule(bytes(32), local, peer, number)
        other_key = r.schedule(b"\x01" * 32, local, peer, number)
        for field in ("draw", "eligible", "priority", "endpoint_priority"):
            self.assertEqual(other_key[field], baseline[field])
        for left, right, trial in (
                (local, peer, number + 1),
                (replace(local, chain=bytes(32)), replace(peer, chain=bytes(32)), number),
                (replace(local, payload=local.payload[:1] + bytes((9, 9, 9, 9))
                         + local.payload[5:]), peer, number),
                (local, replace(peer, payload=peer.payload[:1] + bytes((9, 9, 9, 9))
                                + peer.payload[5:]), number)):
            actual = r.schedule(bytes(32), left, right, trial)
            self.assertNotEqual(actual["draw"], baseline["draw"])
            self.assertNotEqual(actual["priority"], baseline["priority"])
            self.assertNotEqual(actual["endpoint_priority"], baseline["endpoint_priority"])

    def test_proof_rejection(self):
        local, peer = descriptors(3, 51)
        keys, role = r.pair_keys(3, local, peer)
        number = EPOCH * 60 + 3
        context = (keys["auth"], SESSION, number, local, peer, role)
        data = r.feature_data(*context)
        self.assertTrue(r.verify_feature(data, *context))
        for index in (0, 1, 9, 41, 73, 104):
            bad = bytearray(data)
            bad[index] ^= 1
            self.assertFalse(r.verify_feature(bytes(bad), *context))
        for bad in (data[:-1], data + b"\x00", b"\x00" + data[1:]):
            self.assertFalse(r.verify_feature(bad, *context))
        for index, value in ((0, bytes(32)), (1, bytes(32)), (2, number + 1),
                             (3, peer), (4, local), (5, 1 - role)):
            changed = list(context)
            changed[index] = value
            self.assertFalse(r.verify_feature(data, *changed))
        payload = r.feature_payload(data)
        self.assertEqual(len(payload), 171)
        self.assertEqual(payload[:1], b"\x40")
        self.assertEqual(payload[65:66], b"\x69")


if __name__ == "__main__":
    if sys.argv[1:] == ["--generate"]:
        VECTOR_PATH.write_text(json.dumps(build_vectors(), indent=2) + "\n")
        print(f"Wrote {VECTOR_PATH}")
    else:
        unittest.main()
