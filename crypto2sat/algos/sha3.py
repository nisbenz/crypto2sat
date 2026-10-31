"""SHA3-256 (FIPS 202, Keccak-f[1600]), with an optional reduced round count."""
from .. import words as W

FULL_ROUNDS = 24
RATE = 136  # bytes, for SHA3-256

# ROT[x][y]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _rc_bit(t):
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


RC = [sum(_rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)]


def keccak_f(f, A, rounds):
    """A[x][y]: 64-bit lanes."""
    for ir in range(rounds):
        C = [W.xor(f, *A[x]) for x in range(5)]
        D = [W.xor(f, C[(x - 1) % 5], W.rotl(C[(x + 1) % 5], 1)) for x in range(5)]
        A = [[W.xor(f, A[x][y], D[x]) for y in range(5)] for x in range(5)]
        B = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = W.rotl(A[x][y], ROT[x][y])
        A = [[W.xor(f, B[x][y], W.and_(f, W.not_(B[(x + 1) % 5][y]), B[(x + 2) % 5][y]))
              for y in range(5)] for x in range(5)]
        A[0][0] = W.xor(f, A[0][0], W.const(RC[ir], 64))
    return A


def sha3_256(f, msg, rounds=FULL_ROUNDS):
    q = RATE - len(msg) % RATE
    tail = bytes([0x86]) if q == 1 else bytes([0x06]) + bytes(q - 2) + bytes([0x80])
    data = msg + W.byte_words(tail)
    A = [[W.const(0, 64) for _ in range(5)] for _ in range(5)]
    for off in range(0, len(data), RATE):
        block = data[off:off + RATE]
        for i in range(RATE // 8):
            x, y = i % 5, i // 5
            A[x][y] = W.xor(f, A[x][y], W.from_bytes_le(block[8 * i: 8 * i + 8]))
        A = keccak_f(f, A, rounds)
    out = []
    for i in range(4):
        out += W.to_bytes_le(A[i % 5][i // 5])
    return out
