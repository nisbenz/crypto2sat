# crypto2sat

**The world's best-known cryptography, written as 3-SAT.**

OpenAI and Anthropic have each claimed a 2^o(n) algorithm for 3-SAT, which would
disprove the Exponential Time Hypothesis (ETH). Neither claim has been verified yet,
and OpenAI's own paper says its result yields no practical algorithm. But if a fast
SAT algorithm ever *does* show up, these are the files to point it at.

Every instance here is a plain **3-CNF DIMACS file** (no clause has more than 3 literals).
**A satisfying assignment *is* the break:** the RSA factors, the AES key, the SHA-256 preimage.

| Family | Algorithm | What a solution gives you |
|---|---|---|
| Public key | **RSA** | the factors p, q of N, i.e. the private key |
| Public key | **ECDLP** (secp256k1 / toy curves) | the secret scalar k with k·G = Q (Bitcoin keys use secp256k1) |
| Hash | **MD5, SHA-1, SHA-256, SHA3-256** | a preimage: a message m with H(m) = target |
| Block cipher | **AES-128, DES** | the key, from one known plaintext/ciphertext pair |
| Stream cipher | **ChaCha20** | the key, from one known keystream block |

Hashes aren't encrypted, so there's nothing to "decrypt". The hard problem is the **preimage**.

## Sizes (full strength, as generated)

| instance | variables | clauses |
|---|---:|---:|
| des | 14,808 | 74,720 |
| md5 | 22,596 | 97,843 |
| sha1 | 36,008 | 156,296 |
| chacha20 | 41,808 | 186,154 |
| sha256 | 68,144 | 306,383 |
| sha3-256 | 151,104 | 565,248 |
| aes128 | 171,960 | 821,256 |
| rsa-512 | 261,632 | 1,109,248 |
| rsa-1024 | 1,047,552 | 4,446,720 |
| rsa-2048 | 4,192,256 | 17,806,336 |
| ecdlp-toy64 | 3,430,620 | 14,491,914 |
| ecdlp secp256k1 | ~2×10⁸ (estimated) | ~10⁹ (estimated) |

These are *small*. SHA-256 is about 68k variables. A 2^(n/log n) algorithm on n = 68,144
is still about 2^4,200 steps. For an instance like this to fall, a "sub-exponential"
3-SAT algorithm would have to be *very* sub-exponential.

## Use

```bash
pip install -e ".[test]"          # generation itself needs no dependencies

# full-strength SHA-256 preimage of a random 32-byte message
python -m crypto2sat gen sha256 -o sha256.cnf

# invert a digest of your choice (here: an 8-byte message, all 64 bits unknown)
python -m crypto2sat gen sha256 --msg-bytes 8 --target 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -o pw.cnf

# factor a fresh RSA-2048 modulus, or your own N
python -m crypto2sat gen rsa --bits 2048 -o rsa2048.cnf
python -m crypto2sat gen rsa --n 3233 -o tiny.cnf

# AES-128 key recovery, all 10 rounds
python -m crypto2sat gen aes128 -o aes.cnf

# ECDLP on secp256k1 (needs lots of RAM), or on a toy curve
python -m crypto2sat gen ecdlp --curve secp256k1 -o btc.cnf
python -m crypto2sat gen ecdlp --bits 32 -o ec32.cnf
```

Turn the difficulty down to see it work today:

```bash
python -m crypto2sat gen sha256 --rounds 8 --unknown-bits 24 -o easy.cnf
python -m crypto2sat solve easy.cnf          # uses CaDiCaL via python-sat
```

Use any SAT solver, then decode its output. The decoder checks the answer against the real algorithm:

```bash
kissat aes.cnf > model.txt
python -m crypto2sat decode aes.cnf.map.json model.txt
# key = <the 128-bit key in hex>
# verified: this solves the problem
```

Settings:

| flag | applies to | meaning |
|---|---|---|
| `--rounds N` | hashes, ciphers | reduced-round version (default: full) |
| `--unknown-bits N` | hashes, ciphers | leave only the first N secret bits unknown (default: all) |
| `--msg-bytes N` | hashes | message length (default 32) |
| `--target HEX` | hashes | invert this digest instead of a planted one |
| `--bits N` / `--n N` | rsa | modulus size / factor this exact N |
| `--curve`, `--bits`, `--kbits` | ecdlp | `secp256k1` or a toy curve of N bits |
| `--exact3` | all | pad so every clause has **exactly** 3 literals |
| `--seed N` | all | reproducible instances |

Each `.cnf` starts with `c` comment lines giving the problem and which variables hold
the answer. The `.map.json` sidecar has the same information in machine-readable form.

## Where the files are

- `samples/toy/`: small instances a laptop solves in seconds, to check that your setup works.
- Full-strength instances (RSA up to 2048, every algorithm at full rounds) are attached to
  the GitHub Releases as `.cnf.xz`. Or regenerate them in seconds with `python scripts/make_instances.py full`.

## How it works

1. Each algorithm is written once, as a circuit of 2- and 3-input gates (AND, XOR, MUX, MAJ)
   over bit lists ([`crypto2sat/algos/`](crypto2sat/algos)).
2. Known values (plaintext, IV, padding, constants) are plain Python booleans, and every gate
   folds them away. Only the secret bits become variables.
3. Each remaining gate becomes clauses (Tseitin encoding) with at most 3 literals, so the
   result is 3-CNF directly. S-boxes are multiplexer trees. RSA is an array multiplier
   constrained to equal N. ECDLP uses double-and-add over precomputed points, with
   field inverses and products as checked witnesses.
4. Because constants fold, running the same circuit code on all-constant inputs just
   *computes* the algorithm. That's how every circuit is tested against `hashlib` and `pycryptodome`.

## Is it correct?

`pytest` checks:

- every gate against its full truth table, using a SAT solver
- every algorithm against `hashlib` / `pycryptodome` (AES, DES, ChaCha20) on random inputs, multi-block messages included
- **full-round instances of every hash and cipher, plus RSA-256 and a 10-bit ECDLP:** the planted secret satisfies them, and flipping one secret bit makes them UNSAT
- toy instances of every algorithm are actually solved from scratch, and the decoded answer is verified
- the output is valid DIMACS with ≤3 (or, with `--exact3`, exactly 3) literals per clause

## Honest caveats

- The ETH refutations from OpenAI and Anthropic are **unverified claims** under expert review.
  ETH being false would **not** mean P = NP, and it would not automatically make these instances easy.
- Factoring already has a sub-exponential algorithm (the number field sieve). RSA-2048 is safe
  anyway because "sub-exponential" can still mean astronomically slow.
- Modern SAT solvers struggle here. Full-round SHA-256 with just **20** unknown bits
  (a 1-million-case brute force) didn't finish within 2 minutes with CaDiCaL in our tests.
- These encodings are straightforward, not optimized. Smaller encodings exist. PRs welcome.

## License

MIT
