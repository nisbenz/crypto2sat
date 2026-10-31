"""SHA-256 (FIPS 180-4), with an optional reduced round count."""
from math import isqrt

from .. import words as W

FULL_ROUNDS = 64


def _primes(n):
    ps, k = [], 2
    while len(ps) < n:
        if all(k % p for p in ps):
            ps.append(k)
        k += 1
    return ps


def _icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


K = [_icbrt(p << 96) & 0xFFFFFFFF for p in _primes(64)]
H0 = [isqrt(p << 64) & 0xFFFFFFFF for p in _primes(8)]


def pad(msg, length):
    """Merkle-Damgard padding for a message of `length` bytes (one or more blocks)."""
    padlen = (55 - length) % 64
    tail = bytes([0x80]) + bytes(padlen) + (8 * length).to_bytes(8, "big")
    return msg + W.byte_words(tail)


def compress(f, state, block, rounds):
    w = [W.from_bytes_be(block[4 * i: 4 * i + 4]) for i in range(16)]
    for t in range(16, rounds):
        s0 = W.xor(f, W.rotr(w[t - 15], 7), W.rotr(w[t - 15], 18), W.shr(w[t - 15], 3))
        s1 = W.xor(f, W.rotr(w[t - 2], 17), W.rotr(w[t - 2], 19), W.shr(w[t - 2], 10))
        w.append(W.add(f, w[t - 16], s0, w[t - 7], s1))
    a, b, c, d, e, g, h, k = state  # g = "f" in the spec
    for t in range(rounds):
        S1 = W.xor(f, W.rotr(e, 6), W.rotr(e, 11), W.rotr(e, 25))
        t1 = W.add(f, k, S1, W.ch(f, e, g, h), W.const(K[t], 32), w[t])
        S0 = W.xor(f, W.rotr(a, 2), W.rotr(a, 13), W.rotr(a, 22))
        t2 = W.add(f, S0, W.maj(f, a, b, c))
        k, h, g, e, d, c, b, a = h, g, e, W.add(f, d, t1), c, b, a, W.add(f, t1, t2)
    return [W.add(f, x, y) for x, y in zip(state, [a, b, c, d, e, g, h, k])]


def sha256(f, msg, rounds=FULL_ROUNDS):
    """msg: list of 8-bit words. Returns the 32-byte digest as 8-bit words."""
    data = pad(msg, len(msg))
    state = [W.const(x, 32) for x in H0]
    for i in range(0, len(data), 64):
        state = compress(f, state, data[i:i + 64], rounds)
    return [byte for x in state for byte in W.to_bytes_be(x)]
