"""AES-128 encryption (FIPS 197), with an optional reduced round count.

A reduced-round version with r rounds skips MixColumns in round r, the usual
convention in cryptanalysis.
"""
from .. import words as W

FULL_ROUNDS = 10


def _gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return p


def _sbox():
    box = []
    for x in range(256):
        inv = next((y for y in range(256) if _gmul(x, y) == 1), 0)
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        box.append(s ^ 0x63)
    return box


SBOX = _sbox()


def sub_byte(f, b):
    return W.lookup(f, b, SBOX, 8)


def xtime(f, b):
    h = b[7]
    return [h, f.xor2(b[0], h), b[1], f.xor2(b[2], h), f.xor2(b[3], h), b[4], b[5], b[6]]


def key_schedule(f, key, rounds):
    """key: 16 8-bit words -> rounds+1 round keys of 16 8-bit words."""
    w = [key[4 * i: 4 * i + 4] for i in range(4)]
    rcon = 1
    for i in range(4, 4 * (rounds + 1)):
        t = w[i - 1]
        if i % 4 == 0:
            t = [sub_byte(f, b) for b in t[1:] + t[:1]]
            t[0] = W.xor(f, t[0], W.const(rcon, 8))
            rcon = _gmul(rcon, 2)
        w.append([W.xor(f, x, y) for x, y in zip(w[i - 4], t)])
    return [sum(w[4 * r: 4 * r + 4], []) for r in range(rounds + 1)]


def encrypt(f, key, pt, rounds=FULL_ROUNDS):
    """Column-major state: byte i is row i % 4, column i // 4."""
    rk = key_schedule(f, key, rounds)
    s = [W.xor(f, x, y) for x, y in zip(pt, rk[0])]
    for r in range(1, rounds + 1):
        s = [sub_byte(f, b) for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows
        if r != rounds:
            out = []
            for c in range(4):
                a = s[4 * c: 4 * c + 4]
                for i in range(4):
                    x2 = xtime(f, a[i])
                    x3 = W.xor(f, xtime(f, a[(i + 1) % 4]), a[(i + 1) % 4])
                    out.append(W.xor(f, x2, x3, a[(i + 2) % 4], a[(i + 3) % 4]))
            s = out
        s = [W.xor(f, x, y) for x, y in zip(s, rk[r])]
    return s
