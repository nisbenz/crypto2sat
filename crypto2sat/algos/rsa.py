"""RSA: breaking a key = factoring its modulus N = p * q."""
import random

from .. import words as W


def is_prime(n, rounds=40):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(random.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits, rng):
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def keygen(bits, rng):
    """Balanced RSA modulus with exactly `bits` bits."""
    while True:
        p, q = random_prime(bits // 2, rng), random_prime(bits - bits // 2, rng)
        if p != q and (p * q).bit_length() == bits:
            return p, q


def factor(f, n, pbits, qbits):
    """Constrain p * q == n over fresh p (pbits) and q (qbits). Returns (p, q).

    With pbits, qbits < n.bit_length() neither factor can be 1, so every
    solution is a nontrivial factorization.
    """
    p, q = W.fresh(f, pbits), W.fresh(f, qbits)
    W.assert_value(f, W.mul(f, p, q), n)
    return p, q
