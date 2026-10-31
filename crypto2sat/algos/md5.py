"""MD5 (RFC 1321), with an optional reduced step count."""
from math import sin

from .. import words as W

FULL_ROUNDS = 64
K = [int(abs(sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]


def pad(msg, length):
    padlen = (55 - length) % 64
    tail = bytes([0x80]) + bytes(padlen) + (8 * length).to_bytes(8, "little")
    return msg + W.byte_words(tail)


def compress(f, state, block, rounds):
    m = [W.from_bytes_le(block[4 * i: 4 * i + 4]) for i in range(16)]
    a, b, c, d = state
    for i in range(rounds):
        if i < 16:
            fn, g = W.ch(f, b, c, d), i
        elif i < 32:
            fn, g = W.ch(f, d, b, c), (5 * i + 1) % 16
        elif i < 48:
            fn, g = W.xor(f, b, c, d), (3 * i + 5) % 16
        else:
            fn, g = W.xor(f, c, W.or_(f, b, W.not_(d))), (7 * i) % 16
        fn = W.add(f, fn, a, W.const(K[i], 32), m[g])
        a, d, c, b = d, c, b, W.add(f, b, W.rotl(fn, S[i]))
    return [W.add(f, x, y) for x, y in zip(state, [a, b, c, d])]


def md5(f, msg, rounds=FULL_ROUNDS):
    data = pad(msg, len(msg))
    state = [W.const(x, 32) for x in H0]
    for i in range(0, len(data), 64):
        state = compress(f, state, data[i:i + 64], rounds)
    return [byte for x in state for byte in W.to_bytes_le(x)]
