import hashlib
import io
import itertools
import json
import os

import pytest
from Crypto.Cipher import AES, DES, ChaCha20
from pysat.solvers import Cadical153

from crypto2sat import problems
from crypto2sat import words as W
from crypto2sat.__main__ import decode, read_model, write
from crypto2sat.algos import aes, chacha20, des, ecc, md5, sha1, sha2, sha3
from crypto2sat.cnf import Formula, is_const

B = W.byte_words


def solver_for(f):
    s = Cadical153()
    for c in f.clauses():
        s.add_clause(c)
    return s


def bits_of(value, nbits):
    return [bool((value >> (nbits - 1 - i)) & 1) for i in range(nbits)]


# -- gates --------------------------------------------------------------------
GATES = {
    "and2": (2, lambda a, b: a and b),
    "or2": (2, lambda a, b: a or b),
    "xor2": (2, lambda a, b: a != b),
    "xor3": (3, lambda a, b, c: a ^ b ^ c),
    "mux": (3, lambda s, a, b: a if s else b),
    "maj": (3, lambda a, b, c: a + b + c >= 2),
}


@pytest.mark.parametrize("name", GATES)
def test_gate_truth_table(name):
    arity, ref = GATES[name]
    f = Formula()
    ins = [f.var() for _ in range(arity)]
    out = getattr(f, name)(*ins)
    with solver_for(f) as s:
        for vals in itertools.product([False, True], repeat=arity):
            assume = [v if b else -v for v, b in zip(ins, vals)]
            want = ref(*vals)
            assert s.solve(assumptions=assume + [out if want else -out])
            assert not s.solve(assumptions=assume + [-out if want else out])


@pytest.mark.parametrize("name", GATES)
def test_gate_constant_folding(name):
    arity, ref = GATES[name]
    for vals in itertools.product([False, True], repeat=arity):
        f = Formula()
        assert getattr(f, name)(*vals) == ref(*vals) and f.nvars == 0


def test_lookup_and_arith():
    f = Formula()
    table = [(i * 37 + 11) % 256 for i in range(256)]
    x, y = W.fresh(f, 8), W.fresh(f, 8)
    t, s, p = W.lookup(f, x, table, 8), W.add(f, x, y), W.mul(f, x, y)
    with solver_for(f) as sv:
        for a, b in [(0, 0), (3, 250), (255, 255), (77, 128)]:
            assume = [v if bit else -v for v, bit in zip(x + y, W.const(a, 8) + W.const(b, 8))]
            assert sv.solve(assumptions=assume)
            model = set(l for l in sv.get_model() if l > 0)
            bit = lambda l: l if is_const(l) else (l in model) if l > 0 else (-l not in model)
            val = lambda w: sum(1 << i for i, l in enumerate(w) if bit(l))
            assert val(t) == table[a] and val(s) == (a + b) % 256 and val(p) == a * b


# -- the algorithms match reference implementations ------------------------------
@pytest.mark.parametrize("n", [0, 1, 55, 56, 64, 135, 136, 200])
def test_hashes_match_hashlib(n):
    m = os.urandom(n)
    for fn, ref in [(md5.md5, hashlib.md5), (sha1.sha1, hashlib.sha1),
                    (sha2.sha256, hashlib.sha256), (sha3.sha3_256, hashlib.sha3_256)]:
        assert W.bytes_value(fn(Formula(), B(m))) == ref(m).digest()


def test_ciphers_match_pycryptodome():
    for _ in range(3):
        k, p = os.urandom(16), os.urandom(16)
        assert W.bytes_value(aes.encrypt(Formula(), B(k), B(p))) == AES.new(k, AES.MODE_ECB).encrypt(p)
        k, p = os.urandom(8), os.urandom(8)
        assert W.bytes_value(des.encrypt(Formula(), B(k), B(p))) == DES.new(k, DES.MODE_ECB).encrypt(p)
        k, n = os.urandom(32), os.urandom(12)
        assert W.bytes_value(chacha20.block(Formula(), B(k), B(n))) == ChaCha20.new(key=k, nonce=n).encrypt(bytes(64))


def test_secp256k1_generator():
    c = ecc.SECP256K1
    assert c.on_curve(c.G)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert ecc.ec_mul(c, n, c.G) is None


# -- full-size instances: the planted secret satisfies them, a wrong one does not
PLANTED = [
    ("md5", {}), ("sha1", {}), ("sha256", {}), ("sha3-256", {}),
    ("aes128", {}), ("des", {}), ("chacha20", {}),
    ("rsa", {"bits": 256}), ("ecdlp", {"bits": 10}),
]


@pytest.mark.parametrize("algo,kw", PLANTED)
def test_planted_secret(algo, kw):
    inst = problems.build(algo, seed=7, **kw)
    assumptions = []
    for name, bits in inst.answer.items():
        v = inst.secret[name]
        v = int(v, 16) if isinstance(v, str) else v
        assumptions += [b if want else -b for b, want in zip(bits, bits_of(v, len(bits))) if not is_const(b)]
    with solver_for(inst.f) as s:
        assert s.solve(assumptions=assumptions)
        model = set(l for l in s.get_model() if l > 0)
        mapping = json.loads(json.dumps({"answer": {k: [b if is_const(b) else int(b) for b in v]
                                                    for k, v in inst.answer.items()}}))
        assert problems.verify(inst.params, decode(mapping, model))
        wrong = list(assumptions)
        wrong[len(wrong) // 2] = -wrong[len(wrong) // 2]
        assert not s.solve(assumptions=wrong)


# -- toy instances are actually solved from scratch -------------------------------
TOY = [
    ("rsa", {"bits": 32}),
    ("ecdlp", {"bits": 8}),
    ("md5", {"rounds": 16, "unknown_bits": 24}),
    ("sha1", {"rounds": 16, "unknown_bits": 24}),
    ("sha256", {"rounds": 8, "unknown_bits": 24}),
    ("sha3-256", {"rounds": 1, "unknown_bits": 24}),
    ("aes128", {"unknown_bits": 12}),
    ("des", {"unknown_bits": 16}),
    ("chacha20", {"rounds": 4, "unknown_bits": 24}),
]


@pytest.mark.parametrize("algo,kw", TOY)
def test_toy_solve(algo, kw):
    inst = problems.build(algo, seed=3, **kw)
    with solver_for(inst.f) as s:
        assert s.solve()
        model = set(l for l in s.get_model() if l > 0)
    mapping = {"answer": {k: [b if is_const(b) else int(b) for b in v] for k, v in inst.answer.items()}}
    assert problems.verify(inst.params, decode(mapping, model))


# -- file format ----------------------------------------------------------------------
@pytest.mark.parametrize("exact3", [False, True])
def test_dimacs_is_3cnf(tmp_path, exact3):
    inst = problems.build("rsa", bits=24, seed=1)
    path = str(tmp_path / "x.cnf")
    write(inst, path, exact3)
    lines = open(path).read().splitlines()
    header = next(l for l in lines if l.startswith("p "))
    nvars, ncl = map(int, header.split()[2:])
    body = [list(map(int, l.split())) for l in lines if l and l[0] not in "cp"]
    assert len(body) == ncl
    for c in body:
        assert c[-1] == 0 and (len(c) - 1 == 3 if exact3 else 1 <= len(c) - 1 <= 3)
        assert all(0 < abs(x) <= nvars for x in c[:-1])
    mapping = json.load(open(path + ".map.json"))
    with Cadical153(bootstrap_with=[c[:-1] for c in body]) as s:
        assert s.solve()
        out = io.StringIO("v " + " ".join(map(str, s.get_model())) + " 0")
    assert problems.verify(mapping["params"], decode(mapping, read_model(out.read())))
