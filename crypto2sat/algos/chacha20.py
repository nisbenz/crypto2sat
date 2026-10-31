"""ChaCha20 block function (RFC 8439), with an optional reduced round count."""
from .. import words as W

FULL_ROUNDS = 20
SIGMA = b"expand 32-byte k"


def _qr(f, s, a, b, c, d):
    s[a] = W.add(f, s[a], s[b]); s[d] = W.rotl(W.xor(f, s[d], s[a]), 16)
    s[c] = W.add(f, s[c], s[d]); s[b] = W.rotl(W.xor(f, s[b], s[c]), 12)
    s[a] = W.add(f, s[a], s[b]); s[d] = W.rotl(W.xor(f, s[d], s[a]), 8)
    s[c] = W.add(f, s[c], s[d]); s[b] = W.rotl(W.xor(f, s[b], s[c]), 7)


def block(f, key, nonce, counter=0, rounds=FULL_ROUNDS):
    """key: 32 8-bit words, nonce: 12 8-bit words. Returns 64 keystream bytes."""
    le = lambda bs: [W.from_bytes_le(bs[i:i + 4]) for i in range(0, len(bs), 4)]
    init = le(W.byte_words(SIGMA)) + le(key) + [W.const(counter, 32)] + le(nonce)
    s = list(init)
    for r in range(rounds):
        if r % 2 == 0:
            _qr(f, s, 0, 4, 8, 12); _qr(f, s, 1, 5, 9, 13)
            _qr(f, s, 2, 6, 10, 14); _qr(f, s, 3, 7, 11, 15)
        else:
            _qr(f, s, 0, 5, 10, 15); _qr(f, s, 1, 6, 11, 12)
            _qr(f, s, 2, 7, 8, 13); _qr(f, s, 3, 4, 9, 14)
    return [byte for x, y in zip(s, init) for byte in W.to_bytes_le(W.add(f, x, y))]
