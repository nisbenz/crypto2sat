"""Build SAT instances: the secret is variables, everything public is constants.

Every builder plants a random secret (unless the user gives a target), so a
solution is guaranteed to exist. The secret is never written into the CNF.
"""
import random
from dataclasses import dataclass, field

from . import words as W
from .algos import aes, chacha20, des, ecc, md5, rsa, sha1, sha2, sha3
from .cnf import Formula

HASHES = {
    "md5": (md5.md5, md5.FULL_ROUNDS),
    "sha1": (sha1.sha1, sha1.FULL_ROUNDS),
    "sha256": (sha2.sha256, sha2.FULL_ROUNDS),
    "sha3-256": (sha3.sha3_256, sha3.FULL_ROUNDS),
}
CIPHERS = {  # name: (key bytes, plaintext/nonce bytes, full rounds)
    "aes128": (16, 16, aes.FULL_ROUNDS),
    "des": (8, 8, des.FULL_ROUNDS),
    "chacha20": (32, 12, chacha20.FULL_ROUNDS),
}
ALGOS = list(HASHES) + list(CIPHERS) + ["rsa", "ecdlp"]


@dataclass
class Instance:
    f: Formula
    params: dict                                 # public description, enough to verify
    answer: dict = field(default_factory=dict)  # name -> bits, MSB first
    secret: dict = field(default_factory=dict)  # planted solution, for tests only


def msb_bits(byte_words):
    return [b[7 - j] for b in byte_words for j in range(8)]


def secret_input(f, data, unknown, positions=None):
    """8-bit words for `data` where the first `unknown` bits (MSB-first, among
    `positions` if given) are fresh variables and the rest are constants."""
    words = W.byte_words(data)
    positions = range(8 * len(data)) if positions is None else positions
    for i in list(positions)[:unknown]:
        words[i // 8][7 - i % 8] = f.var()
    return words


def _run(fn, *args):
    """Evaluate a circuit on constant inputs."""
    return W.bytes_value(fn(Formula(), *args))


# -- builders -------------------------------------------------------------
def hash_preimage(algo, rounds=None, msg_bytes=32, unknown_bits=None, target=None, seed=None):
    fn, full = HASHES[algo]
    rounds = full if rounds is None else rounds
    rng = random.Random(seed)
    f = Formula()
    if target is not None:  # arbitrary target: every message bit is unknown
        secret, unknown_bits = bytes(msg_bytes), 8 * msg_bytes
        digest = bytes.fromhex(target)
    else:
        secret = rng.randbytes(msg_bytes)
        unknown_bits = 8 * msg_bytes if unknown_bits is None else unknown_bits
        digest = _run(lambda f, m: fn(f, m, rounds), W.byte_words(secret))
    msg = secret_input(f, secret, unknown_bits)
    out = fn(f, msg, rounds)
    for w, b in zip(out, W.byte_words(digest)):
        W.assert_equal(f, w, b)
    params = dict(algo=algo, problem="preimage", rounds=rounds, msg_bytes=msg_bytes,
                  unknown_bits=unknown_bits, target=digest.hex())
    return Instance(f, params, {"message": msb_bits(msg)},
                    {} if target is not None else {"message": secret.hex()})


def _cipher(algo, f, key, data, rounds):
    if algo == "aes128":
        return aes.encrypt(f, key, data, rounds)
    if algo == "des":
        return des.encrypt(f, key, data, rounds)
    return chacha20.block(f, key, data, 0, rounds)


def key_recovery(algo, rounds=None, unknown_bits=None, seed=None):
    klen, dlen, full = CIPHERS[algo]
    rounds = full if rounds is None else rounds
    rng = random.Random(seed)
    key, data = rng.randbytes(klen), rng.randbytes(dlen)
    out = _run(lambda f, k, d: _cipher(algo, f, k, d, rounds), W.byte_words(key), W.byte_words(data))
    # DES ignores every 8th key bit (parity), so only the other 56 count
    positions = [i for i in range(64) if i % 8 != 7] if algo == "des" else None
    total = 56 if algo == "des" else 8 * klen
    unknown_bits = total if unknown_bits is None else unknown_bits
    f = Formula()
    k = secret_input(f, key, unknown_bits, positions)
    for w, b in zip(_cipher(algo, f, k, W.byte_words(data), rounds), W.byte_words(out)):
        W.assert_equal(f, w, b)
    io = {"nonce": data.hex(), "keystream": out.hex()} if algo == "chacha20" else \
         {"plaintext": data.hex(), "ciphertext": out.hex()}
    params = dict(algo=algo, problem="key-recovery", rounds=rounds, unknown_bits=unknown_bits, **io)
    return Instance(f, params, {"key": msb_bits(k)}, {"key": key.hex()})


def rsa_factor(bits=None, n=None, seed=None):
    f = Formula()
    secret = {}
    if n is None:
        p, q = rsa.keygen(bits, random.Random(seed))
        n, secret = p * q, {"p": p, "q": q}
        pbits = qbits = bits // 2 + bits % 2
    else:  # arbitrary composite: smaller factor fits in half the bits, larger in n-1
        bits = n.bit_length()
        pbits, qbits = (bits + 1) // 2, bits - 1
    pw, qw = rsa.factor(f, n, pbits, qbits)
    params = dict(algo="rsa", problem="factor", bits=bits, n=str(n))
    return Instance(f, params, {"p": pw[::-1], "q": qw[::-1]}, secret)


def ecdlp(curve="toy", bits=24, kbits=None, seed=None):
    c = ecc.SECP256K1 if curve == "secp256k1" else ecc.toy_curve(bits)
    kbits = c.p.bit_length() if kbits is None else kbits
    rng = random.Random(seed)
    k = rng.getrandbits(kbits) | 1
    Q = ecc.ec_mul(c, k, c.G)
    while True:  # pick an offset A that avoids every exceptional addition
        A = ecc.ec_mul(c, rng.getrandbits(c.p.bit_length()), c.G)
        if A is None:
            continue
        try:
            R = ecc.scalar_mul(Formula(), c, W.const(k, kbits), A)
        except ValueError:
            continue
        target = ecc.ec_add(c, A, Q)
        if target is not None and (W.value(R[0]), W.value(R[1])) == target:
            break
    f = Formula()
    kw = W.fresh(f, kbits)
    R = ecc.scalar_mul(f, c, kw, A)
    W.assert_value(f, R[0], target[0])
    W.assert_value(f, R[1], target[1])
    params = dict(algo="ecdlp", problem="discrete-log", curve=c.name, p=str(c.p), a=c.a, b=c.b,
                  G=[str(c.gx), str(c.gy)], Q=[str(Q[0]), str(Q[1])], A=[str(A[0]), str(A[1])],
                  kbits=kbits)
    return Instance(f, params, {"k": kw[::-1]}, {"k": k})


def build(algo, **kw):
    kw = {k: v for k, v in kw.items() if v is not None}
    if algo in HASHES:
        return hash_preimage(algo, **kw)
    if algo in CIPHERS:
        return key_recovery(algo, **kw)
    if algo == "rsa":
        return rsa_factor(**kw)
    if algo == "ecdlp":
        return ecdlp(**kw)
    raise ValueError(f"unknown algorithm {algo!r}; choose from {', '.join(ALGOS)}")


# -- checking a recovered answer -----------------------------------------------
def verify(params, answer):
    """answer: name -> int. True if it really solves the public problem."""
    algo = params["algo"]
    if algo in HASHES:
        fn, _ = HASHES[algo]
        msg = answer["message"].to_bytes(params["msg_bytes"], "big")
        return _run(lambda f, m: fn(f, m, params["rounds"]), W.byte_words(msg)).hex() == params["target"]
    if algo in CIPHERS:
        klen = CIPHERS[algo][0]
        key = answer["key"].to_bytes(klen, "big")
        data = bytes.fromhex(params.get("plaintext") or params["nonce"])
        out = _run(lambda f, k, d: _cipher(algo, f, k, d, params["rounds"]), W.byte_words(key), W.byte_words(data))
        return out.hex() == (params.get("ciphertext") or params["keystream"])
    if algo == "rsa":
        p, q, n = answer["p"], answer["q"], int(params["n"])
        return p > 1 and q > 1 and p * q == n
    if algo == "ecdlp":
        c = ecc.Curve(params["curve"], int(params["p"]), params["a"], params["b"], *map(int, params["G"]))
        return ecc.ec_mul(c, answer["k"], c.G) == tuple(map(int, params["Q"]))
    raise ValueError(algo)
