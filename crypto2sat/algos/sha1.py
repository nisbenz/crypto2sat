"""SHA-1 (FIPS 180-4), with an optional reduced round count."""
from .. import words as W
from .sha2 import pad

FULL_ROUNDS = 80
H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def compress(f, state, block, rounds):
    w = [W.from_bytes_be(block[4 * i: 4 * i + 4]) for i in range(16)]
    for t in range(16, rounds):
        w.append(W.rotl(W.xor(f, w[t - 3], w[t - 8], w[t - 14], w[t - 16]), 1))
    a, b, c, d, e = state
    for t in range(rounds):
        if t < 20:
            fn, k = W.ch(f, b, c, d), 0x5A827999
        elif t < 40:
            fn, k = W.xor(f, b, c, d), 0x6ED9EBA1
        elif t < 60:
            fn, k = W.maj(f, b, c, d), 0x8F1BBCDC
        else:
            fn, k = W.xor(f, b, c, d), 0xCA62C1D6
        tmp = W.add(f, W.rotl(a, 5), fn, e, W.const(k, 32), w[t])
        a, b, c, d, e = tmp, a, W.rotl(b, 30), c, d
    return [W.add(f, x, y) for x, y in zip(state, [a, b, c, d, e])]


def sha1(f, msg, rounds=FULL_ROUNDS):
    data = pad(msg, len(msg))
    state = [W.const(x, 32) for x in H0]
    for i in range(0, len(data), 64):
        state = compress(f, state, data[i:i + 64], rounds)
    return [byte for x in state for byte in W.to_bytes_be(x)]
