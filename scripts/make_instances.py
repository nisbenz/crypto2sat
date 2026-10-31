"""Generate the instance sets.

    python scripts/make_instances.py toy    # small, solvable today -> samples/toy/
    python scripts/make_instances.py full   # real sizes -> dist/*.cnf.xz (release assets)
    python scripts/make_instances.py stats  # print sizes of the full set without writing
"""
import lzma
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto2sat import problems  # noqa: E402
from crypto2sat.__main__ import write  # noqa: E402

SEED = 2026

TOY = {
    "rsa-40": ("rsa", dict(bits=40)),
    "ecdlp-toy8": ("ecdlp", dict(bits=8)),
    "md5-r16-u24": ("md5", dict(rounds=16, unknown_bits=24)),
    "sha1-r16-u24": ("sha1", dict(rounds=16, unknown_bits=24)),
    "sha256-r8-u24": ("sha256", dict(rounds=8, unknown_bits=24)),
    "sha3-256-r1-u24": ("sha3-256", dict(rounds=1, unknown_bits=24)),
    "aes128-u12": ("aes128", dict(unknown_bits=12)),
    "des-u16": ("des", dict(unknown_bits=16)),
    "chacha20-r4-u24": ("chacha20", dict(rounds=4, unknown_bits=24)),
}

FULL = {
    "rsa-512": ("rsa", dict(bits=512)),
    "rsa-1024": ("rsa", dict(bits=1024)),
    "rsa-2048": ("rsa", dict(bits=2048)),
    "ecdlp-toy64": ("ecdlp", dict(bits=64)),
    "md5": ("md5", {}),
    "sha1": ("sha1", {}),
    "sha256": ("sha256", {}),
    "sha3-256": ("sha3-256", {}),
    "aes128": ("aes128", {}),
    "des": ("des", {}),
    "chacha20": ("chacha20", {}),
}


def main(which):
    sets = {"toy": TOY, "full": FULL, "stats": FULL}[which]
    outdir = {"toy": "samples/toy", "full": "dist"}.get(which)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    print("| instance | variables | clauses |\n|---|---:|---:|")
    for name, (algo, kw) in sets.items():
        t = time.time()
        inst = problems.build(algo, seed=SEED, **kw)
        if which == "toy":
            write(inst, f"{outdir}/{name}.cnf")
        elif which == "full":
            path = f"{outdir}/{name}.cnf"
            write(inst, path)
            with open(path, "rb") as src, lzma.open(path + ".xz", "wb", preset=6) as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            os.remove(path)
        print(f"| {name} | {inst.f.nvars:,} | {inst.f.nclauses:,} |  ({time.time() - t:.0f}s)",
              file=sys.stdout, flush=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "toy")
