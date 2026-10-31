"""3-CNF formula builder.

A *bit* is either a Python bool (a known constant) or a nonzero int (a DIMACS
literal). Every gate folds constants away, so running an algorithm on all-constant
inputs just computes it, and running it on variables emits clauses. Every gate is
a Tseitin encoding of a gate with at most 3 inputs, so no clause has more than
3 literals.
"""
from array import array


def is_const(x):
    return x.__class__ is bool


def neg(x):
    return (not x) if is_const(x) else -x


class Formula:
    def __init__(self):
        self.nvars = 0
        self.nclauses = 0
        self.lits = array("i")  # flat clause list, each clause ends with 0
        self.unsat = False      # set when a constant contradiction is asserted

    # -- primitives -------------------------------------------------------
    def var(self):
        self.nvars += 1
        return self.nvars

    def clause(self, *lits):
        assert 0 < len(lits) <= 3
        self.lits.extend(lits)
        self.lits.append(0)
        self.nclauses += 1

    def fix(self, x, value):
        """Constrain bit x to equal the constant value."""
        if is_const(x):
            if x != value:
                self.unsat = True
        else:
            self.clause(x if value else -x)

    def equal(self, a, b):
        """Constrain bits a and b to be equal."""
        if is_const(a):
            self.fix(b, a)
        elif is_const(b):
            self.fix(a, b)
        elif a != b:
            self.clause(-a, b)
            self.clause(a, -b)

    # -- gates ------------------------------------------------------------
    def and2(self, a, b):
        if is_const(a):
            return b if a else False
        if is_const(b):
            return a if b else False
        if a == b:
            return a
        if a == -b:
            return False
        z = self.var()
        self.clause(-z, a)
        self.clause(-z, b)
        self.clause(z, -a, -b)
        return z

    def or2(self, a, b):
        return neg(self.and2(neg(a), neg(b)))

    def xor2(self, a, b):
        if is_const(a):
            return neg(b) if a else b
        if is_const(b):
            return neg(a) if b else a
        if a == b:
            return False
        if a == -b:
            return True
        z = self.var()
        self.clause(-z, a, b)
        self.clause(-z, -a, -b)
        self.clause(z, -a, b)
        self.clause(z, a, -b)
        return z

    def xor3(self, a, b, c):
        return self.xor2(self.xor2(a, b), c)

    def mux(self, s, a, b):
        """s ? a : b"""
        if is_const(s):
            return a if s else b
        if a == b and a.__class__ is b.__class__:
            return a
        if is_const(a):
            return self.or2(s, b) if a else self.and2(neg(s), b)
        if is_const(b):
            return self.or2(neg(s), a) if b else self.and2(s, a)
        z = self.var()
        self.clause(-s, -a, z)
        self.clause(-s, a, -z)
        self.clause(s, -b, z)
        self.clause(s, b, -z)
        self.clause(-a, -b, z)  # redundant, helps propagation
        self.clause(a, b, -z)
        return z

    def maj(self, a, b, c):
        if is_const(a):
            return self.or2(b, c) if a else self.and2(b, c)
        if is_const(b):
            return self.or2(a, c) if b else self.and2(a, c)
        if is_const(c):
            return self.or2(a, b) if c else self.and2(a, b)
        if a == b:
            return a
        if a == -b:
            return c
        if a == c:
            return a
        if a == -c:
            return b
        if b == c:
            return b
        if b == -c:
            return a
        z = self.var()
        self.clause(-a, -b, z)
        self.clause(-a, -c, z)
        self.clause(-b, -c, z)
        self.clause(a, b, -z)
        self.clause(a, c, -z)
        self.clause(b, c, -z)
        return z

    # -- output -----------------------------------------------------------
    def clauses(self):
        cur = []
        for x in self.lits:
            if x == 0:
                yield cur
                cur = []
            else:
                cur.append(x)

    def write_dimacs(self, fp, comments=(), exact3=False):
        """Write as DIMACS. With exact3, every clause gets exactly 3 literals
        (shorter clauses are padded using 2 shared helper variables)."""
        nvars, nclauses = self.nvars, self.nclauses
        if self.unsat:
            nvars = max(nvars, 1)
            nclauses += 2
        if exact3:
            y, z = nvars + 1, nvars + 2
            nvars += 2
            n1 = n2 = 0
            for c in self.clauses():
                if len(c) == 1:
                    n1 += 1
                elif len(c) == 2:
                    n2 += 1
            if self.unsat:
                n1 += 2
            nclauses += 3 * n1 + n2
        for line in comments:
            fp.write(f"c {line}\n")
        fp.write(f"p cnf {nvars} {nclauses}\n")

        def emit(c):
            if exact3 and len(c) == 1:
                a = c[0]
                fp.write(f"{a} {y} {z} 0\n{a} {y} {-z} 0\n{a} {-y} {z} 0\n{a} {-y} {-z} 0\n")
            elif exact3 and len(c) == 2:
                a, b = c
                fp.write(f"{a} {b} {y} 0\n{a} {b} {-y} 0\n")
            else:
                fp.write(" ".join(map(str, c)) + " 0\n")

        if self.unsat:
            # constant contradiction: x and not x
            emit([1])
            emit([-1])
        buf = []
        for x in self.lits:
            if x == 0:
                emit(buf)
                buf = []
            else:
                buf.append(x)
