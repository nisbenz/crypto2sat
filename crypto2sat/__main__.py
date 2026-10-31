"""Command line: generate instances, decode solver output, or solve small ones."""
import argparse
import json
import os
import sys

from . import problems
from .cnf import is_const


def _bits_json(bits):
    return [b if is_const(b) else int(b) for b in bits]


def write(inst, path, exact3=False):
    p = inst.params
    comments = [
        "crypto2sat - https://github.com/nisbenz/crypto2sat",
        "problem: " + " ".join(f"{k}={v}" for k, v in p.items()),
        "solve it, then: python -m crypto2sat decode " + os.path.basename(path) + ".map.json <solver-output>",
    ]
    for name, bits in inst.answer.items():
        lits = " ".join("T" if b is True else "F" if b is False else str(b) for b in bits)
        comments.append(f"answer {name} (MSB first; T/F = known constant): {lits}")
    with open(path, "w") as fp:
        inst.f.write_dimacs(fp, comments, exact3)
    with open(path + ".map.json", "w") as fp:
        json.dump({"params": p, "answer": {k: _bits_json(v) for k, v in inst.answer.items()}}, fp)


def read_model(text):
    true = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("v "):
            line = line[2:]
        if not line or not (line[0] == "-" or line[0].isdigit()):
            continue
        true.update(x for x in map(int, line.split()) if x > 0)
    return true


def decode(mapping, true):
    answer = {}
    for name, bits in mapping["answer"].items():
        v = 0
        for b in bits:
            bit = b if isinstance(b, bool) else (b in true) if b > 0 else (-b not in true)
            v = (v << 1) | bit
        answer[name] = v
    return answer


def show(params, answer):
    for name, v in answer.items():
        print(f"{name} = {v}" if params["algo"] in ("rsa", "ecdlp") else f"{name} = {v:x}")
    ok = problems.verify(params, answer)
    print("verified: this solves the problem" if ok else "NOT a valid solution")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(prog="crypto2sat", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate a 3-CNF instance")
    g.add_argument("algo", choices=problems.ALGOS)
    g.add_argument("-o", "--out", required=True)
    g.add_argument("--rounds", type=int, help="reduced rounds (default: full)")
    g.add_argument("--unknown-bits", type=int, help="secret bits left unknown (default: all)")
    g.add_argument("--msg-bytes", type=int, help="hash message length (default 32)")
    g.add_argument("--target", help="hash: digest (hex) to invert instead of a planted one")
    g.add_argument("--bits", type=int, help="rsa: modulus size; ecdlp: toy field size")
    g.add_argument("--n", type=int, help="rsa: factor this modulus instead of a fresh one")
    g.add_argument("--curve", choices=["toy", "secp256k1"], help="ecdlp curve (default toy)")
    g.add_argument("--kbits", type=int, help="ecdlp: bits of the secret scalar")
    g.add_argument("--seed", type=int)
    g.add_argument("--exact3", action="store_true", help="pad so every clause has exactly 3 literals")

    d = sub.add_parser("decode", help="turn a solver's model into the answer")
    d.add_argument("map")
    d.add_argument("model", nargs="?", help="solver output file (default stdin)")

    s = sub.add_parser("solve", help="solve a small instance with python-sat (CaDiCaL)")
    s.add_argument("cnf")

    a = ap.parse_args(argv)
    if a.cmd == "gen":
        kw = dict(rounds=a.rounds, unknown_bits=a.unknown_bits, msg_bytes=a.msg_bytes,
                  target=a.target, bits=a.bits, n=a.n, curve=a.curve, kbits=a.kbits, seed=a.seed)
        allowed = {
            **{h: ("rounds", "unknown_bits", "msg_bytes", "target", "seed") for h in problems.HASHES},
            **{c: ("rounds", "unknown_bits", "seed") for c in problems.CIPHERS},
            "rsa": ("bits", "n", "seed"),
            "ecdlp": ("curve", "bits", "kbits", "seed"),
        }[a.algo]
        extra = [k for k, v in kw.items() if v is not None and k not in allowed]
        if extra:
            ap.error(f"{a.algo} does not take --{', --'.join(e.replace('_', '-') for e in extra)}")
        if a.algo == "rsa" and a.bits is None and a.n is None:
            ap.error("rsa needs --bits or --n")
        inst = problems.build(a.algo, **{k: v for k, v in kw.items() if k in allowed})
        write(inst, a.out, a.exact3)
        print(f"{a.out}: {inst.f.nvars} variables, {inst.f.nclauses} clauses")
    elif a.cmd == "decode":
        mapping = json.load(open(a.map))
        text = open(a.model).read() if a.model else sys.stdin.read()
        if "UNSAT" in text:
            sys.exit("solver says UNSAT")
        sys.exit(0 if show(mapping["params"], decode(mapping, read_model(text))) else 1)
    elif a.cmd == "solve":
        from pysat.formula import CNF
        from pysat.solvers import Cadical153
        with Cadical153(bootstrap_with=CNF(from_file=a.cnf).clauses) as solver:
            if not solver.solve():
                sys.exit("UNSAT")
            mapping = json.load(open(a.cnf + ".map.json"))
            sys.exit(0 if show(mapping["params"], decode(mapping, set(x for x in solver.get_model() if x > 0))) else 1)


if __name__ == "__main__":
    main()
