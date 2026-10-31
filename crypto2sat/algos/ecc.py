"""Elliptic-curve discrete log (ECDLP) on short Weierstrass curves y^2 = x^3 + ax + b.

Circuit for k*G: with constant points P_i = 2^i * G and a constant offset A,
    R = A;  for each bit i:  R = k_i ? R + P_i : R
then R must equal A + Q. The offset keeps R away from the point at infinity.
Point addition is affine; each field inverse / product is a *witness* checked by
one multiplication (a*b == q*p + r, r < p), which is far smaller than computing it.
"""
from dataclasses import dataclass

from .. import words as W


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int

    @property
    def G(self):
        return (self.gx, self.gy)

    def on_curve(self, P):
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0


SECP256K1 = Curve(
    "secp256k1", 2**256 - 2**32 - 977, 0, 7,
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def toy_curve(bits):
    """A small y^2 = x^3 + 7 curve over a `bits`-bit prime p = 3 mod 4."""
    from .rsa import is_prime
    p = (1 << (bits - 1)) + 3
    while not (is_prime(p) and p % 4 == 3):
        p += 4
    x = 1
    while True:
        rhs = (x ** 3 + 7) % p
        y = pow(rhs, (p + 1) // 4, p)
        if rhs and y * y % p == rhs:
            return Curve(f"toy{bits}", p, 0, 7, x, y)
        x += 1


# -- plain integer point arithmetic (None = point at infinity) ----------------
def ec_add(c, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2), p = P, Q, c.p
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + c.a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def ec_mul(c, k, P):
    R = None
    while k:
        if k & 1:
            R = ec_add(c, R, P)
        P, k = ec_add(c, P, P), k >> 1
    return R


# -- circuits over n-bit field elements -----------------------------------------
def _modadd(f, a, b, p):
    n = len(a)
    s, c = W.add_carry(f, a, b)
    s = s + [c]
    t, borrow = W.sub_borrow(f, s, W.const(p, n + 1))
    return W.mux(f, borrow, s, t)[:n]


def _modsub(f, a, b, p):
    d, borrow = W.sub_borrow(f, a, b)
    return W.mux(f, borrow, W.add(f, d, W.const(p, len(d))), d)


def _lt_const(f, a, p):
    return W.sub_borrow(f, a, W.const(p, len(a)))[1]


def _modmul(f, a, b, p):
    n = len(a)
    q = W.witness(f, n, lambda x, y: x * y // p, a, b)
    r = W.witness(f, n, lambda x, y: x * y % p, a, b)
    rhs = W.add(f, W.zext(W.mul(f, q, W.const(p, n)), 2 * n + 1), W.zext(r, 2 * n + 1))
    W.assert_equal(f, W.mul(f, a, b), rhs)
    f.fix(_lt_const(f, r, p), True)
    return r


def _add_const_point(f, c, R, P):
    """R (variable point) + P (constant point), assuming R.x != P.x."""
    p, n = c.p, len(R[0])
    (x1, y1), (x2, y2) = R, (W.const(P[0], n), W.const(P[1], n))
    lam = W.witness(f, n, lambda a, b: (P[1] - b) * pow(P[0] - a, -1, p) % p, x1, y1)
    f.fix(_lt_const(f, lam, p), True)
    W.assert_equal(f, _modmul(f, lam, _modsub(f, x2, x1, p), p), _modsub(f, y2, y1, p))
    x3 = _modsub(f, _modsub(f, _modmul(f, lam, lam, p), x1, p), x2, p)
    y3 = _modsub(f, _modmul(f, lam, _modsub(f, x1, x3, p), p), y1, p)
    return (x3, y3)


def scalar_mul(f, c, k, A):
    """Circuit for A + k*G. k: bit list (LSB first). A: constant offset point."""
    n = c.p.bit_length()
    R = (W.const(A[0], n), W.const(A[1], n))
    P = c.G
    for ki in k:
        if P is not None:
            S = _add_const_point(f, c, R, P)
            R = (W.mux(f, ki, S[0], R[0]), W.mux(f, ki, S[1], R[1]))
        P = ec_add(c, P, P)
    return R
