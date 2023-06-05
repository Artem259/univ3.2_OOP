from gmpy2 import powmod, xmpz, invert, to_binary, is_prime
from random import randrange
from hashlib import sha1


def _p_q_gen(L, N):
    g = N
    n = (L - 1) // g
    b = (L - 1) % g
    while True:
        while True:
            s = xmpz(randrange(1, 2 ** g))
            a = sha1(to_binary(s)).hexdigest()
            zz = xmpz((s + 1) % (2 ** g))
            z = sha1(to_binary(zz)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2 ** (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break
        i = 0
        j = 2
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1


def _generate_g(p, q):
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def _generate_params(L, N):
    p, q = _p_q_gen(L, N)
    g = _generate_g(p, q)
    return p, q, g


def _validate_signature(r, s, q):
    return not (0 > r > q or 0 > s > q)


class Dsa:
    def __init__(self):
        N = 224
        L = 2048
        self.p, self.q, self.g = _generate_params(L, N)

    def public_key_gen(self, private_key):
        if not (2 < private_key < self.q):
            raise ValueError("2 < private_key < self.q")
        return powmod(self.g, private_key, self.p)

    def sign(self, message, private_key):
        while True:
            k = randrange(2, self.q)
            r = powmod(self.g, k, self.p) % self.q
            m = int(sha1(message).hexdigest(), 16)
            try:
                s = (invert(k, self.q) * (m + private_key * r)) % self.q
                return r, s
            except ZeroDivisionError:
                pass

    def verify(self, message, r, s, public_key):
        if not _validate_signature(r, s, self.q):
            return False
        try:
            w = invert(s, self.q)
        except ZeroDivisionError:
            return False
        m = int(sha1(message).hexdigest(), 16)
        u1 = (m * w) % self.q
        u2 = (r * w) % self.q

        v = (powmod(self.g, u1, self.p) * powmod(public_key, u2, self.p)) % self.p % self.q
        return v == r
