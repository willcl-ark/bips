"""Test-only reference for the version-0 holepunch cryptographic formulas.

No networking or lifecycle implementation. This code is not constant-time and
MUST NOT handle production secrets. IPv4 policy uses Python's address classes;
production implementations must additionally apply their own routing policy.
"""

import hashlib
import hmac
import importlib.util
import ipaddress
from dataclasses import dataclass
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "bip324", Path(__file__).resolve().parents[1] / "bip-0324/reference.py")
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)


def sha256(data):
    return hashlib.sha256(data).digest()


def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


FEATURE_ID = sha256(b"BitcoinHolePunch/v0/feature").hex().encode("ascii")


def public_key(secret):
    if not 1 <= secret < ec.GE.ORDER:
        raise ValueError("invalid secret scalar")
    point = secret * ec.SECP256K1_G
    return bytes([2 + (int(point.y) & 1)]) + point.x.to_bytes()


def decode_key(encoded):
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed public key")
    x = ec.FE.from_bytes(encoded[1:])
    point = None if x is None else ec.GE.lift_x(x)
    if point is None:
        raise ValueError("invalid secp256k1 x coordinate")
    if (int(point.y) & 1) != (encoded[0] & 1):
        point = ec.GE(point.x, -point.y)
    return point


@dataclass(frozen=True)
class Descriptor:
    chain: bytes
    payload: bytes
    port: int

    def __post_init__(self):
        if len(self.chain) != 32 or len(self.payload) != 42 or self.payload[0] != 0:
            raise ValueError("invalid descriptor encoding")
        address = ipaddress.IPv4Address(self.payload[1:5])
        if not address.is_global or address.is_multicast or not 1 <= self.port <= 65535:
            raise ValueError("invalid destination")
        decode_key(self.key)

    @property
    def key(self):
        return self.payload[9:]

    @property
    def epoch(self):
        return int.from_bytes(self.payload[5:9], "little")

    @property
    def endpoint(self):
        return self.payload[1:5] + self.port.to_bytes(2, "big")

    @property
    def encoded(self):
        return self.chain + self.payload + self.endpoint[4:]

    @property
    def id(self):
        return sha256(self.encoded)


def advertisement(ipv4, epoch, key):
    decode_key(key)
    return b"\x00" + ipaddress.IPv4Address(ipv4).packed + epoch.to_bytes(4, "little") + key


def compact_size(value):
    for limit, prefix, width in ((253, b"", 1), (2**16, b"\xfd", 2),
                                 (2**32, b"\xfe", 4), (2**64, b"\xff", 8)):
        if 0 <= value < limit:
            return prefix + value.to_bytes(width, "little")
    raise ValueError("invalid CompactSize")


def addrv2(descriptor, timestamp, services, network_id):
    """One-record message payload; network_id is an input, not an assignment."""
    return (b"\x01" + timestamp.to_bytes(4, "little") + compact_size(services)
            + bytes([network_id]) + b"\x2a" + descriptor.payload
            + descriptor.endpoint[4:])


def pair_keys(secret, local, peer):
    if (local.chain != peer.chain or local.epoch != peer.epoch
            or local.endpoint == peer.endpoint or local.key == peer.key):
        raise ValueError("invalid pair")
    if public_key(secret) != local.key:
        raise ValueError("secret does not match local descriptor")
    lo, hi = sorted((local, peer), key=lambda item: item.key)
    z = (secret * decode_key(peer.key)).x.to_bytes()
    salt = sha256(b"BitcoinHolePunch/v0" + lo.encoded + hi.encoded)
    prk = mac(salt, z)
    return {"z": z, "salt": salt, "prk": prk,
            "schedule": mac(prk, b"schedule\x01"),
            "auth": mac(prk, b"authentication\x01")}, int(local != lo)


def eligible(draw):
    return int.from_bytes(draw, "big") < 2**251


def offset(time_draw):
    return 5000 + int.from_bytes(time_draw, "big") * 30000 // 2**256


def schedule(key, epoch, round_number):
    if round_number // 60 != epoch:
        raise ValueError("round outside descriptor epoch")
    encoded_round = round_number.to_bytes(8, "little")
    draw = mac(key, b"eligibility" + encoded_round)
    time_draw = mac(key, b"time" + encoded_round)
    delay = offset(time_draw)
    return {"draw": draw.hex(), "eligible": eligible(draw),
            "time_draw": time_draw.hex(), "offset_ms": delay,
            "start_ms": 60000 * round_number + delay,
            "priority": mac(key, b"priority" + encoded_round).hex()}


def feature_data(key, session_id, round_number, sender, receiver, role):
    if len(session_id) != 32 or role not in (0, 1):
        raise ValueError("invalid proof context")
    context = round_number.to_bytes(8, "little") + sender.id + receiver.id
    proof = mac(key, b"connection" + session_id + context + bytes([role]))
    return b"\x00" + context + proof


def verify_feature(data, key, session_id, round_number, sender, receiver, role):
    expected = feature_data(key, session_id, round_number, sender, receiver, role)
    return len(data) == 105 and data[:73] == expected[:73] and hmac.compare_digest(
        data[73:], expected[73:])


def feature_payload(data):
    """BIP434 message payload, excluding BIP324 message type 37/0x25."""
    return compact_size(len(FEATURE_ID)) + FEATURE_ID + compact_size(len(data)) + data
