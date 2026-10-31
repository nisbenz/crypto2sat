"""Fixed-width words as lists of bits, least significant bit first.

Each operation takes the Formula `f` and returns new bits. Since the gates fold
constants, the same code evaluates concretely when every input is a constant.
"""
from .cnf import is_const, neg


# -- construction / reading -----------------------------------------------
def const(value, n):
    return [bool((value >> i) & 1) for i in range(n)]


def fresh(f, n):
    return [f.var() for _ in range(n)]


def value(w):
    """Integer value of an all-constant word, else None."""
    if not all(is_const(b) for b in w):
        return None
    return sum(1 << i for i, b in enumerate(w) if b)


def byte_words(data):
    """bytes -> list of 8-bit constant words."""
    return [const(b, 8) for b in data]


def bytes_value(ws):
    vals = [value(w) for w in ws]
    return None if None in vals else bytes(vals)


def from_bytes_be(bs):
    """List of 8-bit words -> one word, big-endian byte order."""
    out = []
    for b in reversed(bs):
        out += b
    return out


def from_bytes_le(bs):
    out = []
    for b in bs:
        out += b
    return out


def to_bytes_be(w):
    n = len(w) // 8
    return [w[8 * (n - 1 - i): 8 * (n - i)] for i in range(n)]


def to_bytes_le(w):
    return [w[8 * i: 8 * i + 8] for i in range(len(w) // 8)]


# -- bitwise ----------------------------------------------------------------
def xor(f, *ws):
    out = ws[0]
    for w in ws[1:]:
        out = [f.xor2(a, b) for a, b in zip(out, w)]
    return out


def and_(f, a, b):
    return [f.and2(x, y) for x, y in zip(a, b)]


def or_(f, a, b):
    return [f.or2(x, y) for x, y in zip(a, b)]


def not_(w):
    return [neg(x) for x in w]


def mux(f, s, a, b):
    """Per-bit select with a single selector bit s: s ? a : b."""
    return [f.mux(s, x, y) for x, y in zip(a, b)]


def ch(f, s, a, b):
    """Per-bit select: s[i] ? a[i] : b[i]."""
    return [f.mux(x, y, z) for x, y, z in zip(s, a, b)]


def maj(f, a, b, c):
    return [f.maj(x, y, z) for x, y, z in zip(a, b, c)]


def rotl(w, k):
    k %= len(w)
    return w[len(w) - k:] + w[:len(w) - k]


def rotr(w, k):
    return rotl(w, len(w) - k % len(w))


def shr(w, k):
    return w[k:] + [False] * k


def shl(w, k):
    return [False] * k + w[:len(w) - k]


# -- arithmetic -------------------------------------------------------------
def add_carry(f, a, b, cin=False):
    """Ripple-carry a + b + cin. Returns (sum mod 2^n, carry out)."""
    s, c = [], cin
    for x, y in zip(a, b):
        s.append(f.xor3(x, y, c))
        c = f.maj(x, y, c)
    return s, c


def add(f, *ws):
    out = ws[0]
    for w in ws[1:]:
        out = add_carry(f, out, w)[0]
    return out


def sub_borrow(f, a, b):
    """a - b mod 2^n, and borrow (True when a < b)."""
    d, c = add_carry(f, a, not_(b), True)
    return d, neg(c)


def zext(w, n):
    return w + [False] * (n - len(w))


def mul(f, a, b):
    """Full product, width len(a) + len(b) (array multiplier)."""
    na = len(a)
    acc = [False] * (na + len(b))
    for i, bi in enumerate(b):
        if bi is False:
            continue
        row = [f.and2(x, bi) for x in a]
        s, c = add_carry(f, acc[i:i + na], row)
        acc[i:i + na] = s
        acc[i + na] = c
    return acc


def assert_equal(f, a, b):
    n = max(len(a), len(b))
    for x, y in zip(zext(a, n), zext(b, n)):
        f.equal(x, y)


def assert_value(f, w, v):
    for x, y in zip(w, const(v, len(w))):
        f.fix(x, y)
    if v >> len(w):
        f.unsat = True


def lookup(f, w, table, nout):
    """Table lookup table[value(w)] via a mux tree per output bit."""
    n = len(w)
    out = []
    for j in range(nout):
        level = [bool((table[i] >> j) & 1) for i in range(1 << n)]
        for k in range(n):  # fold on input bit k (lowest first)
            s = w[k]
            level = [f.mux(s, level[i + 1], level[i]) for i in range(0, len(level), 2)]
        out.append(level[0])
    return out


def witness(f, n, compute, *deps):
    """n-bit helper value: constant compute(*deps) if all deps are constants,
    else fresh variables that the caller must constrain."""
    vals = [value(d) for d in deps]
    if None in vals:
        return fresh(f, n)
    return const(compute(*vals), n)
