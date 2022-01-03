import random
import math
import string
import numpy as np
import pickle


class RSA:

    def __init__(self, private_key=None, public_key=None, load_file=None):
        self.private_key, self.public_key, self.load_file = private_key, public_key, load_file
        self.chars = string.printable
        if self.load_file is not None:
            self.load(self.load_file)

    def sieve(self, n):
        nums = np.arange(2, n + 1, 1)
        marker = np.zeros(n)
        primes = []
        for index, num in enumerate(nums):
            if marker[index] == 0:
                primes.append(num)
                for j in range(index + num, len(nums), num):
                    marker[j] = 1
        return primes

    def hcf(self, i, j):
        while True:
            temp = i % j
            if temp == 0:
                return j
            i = j
            j = temp

    def get_coprimes(self, n, max=0):
        coprimes = []
        for i in range(n + 1):
            if self.hcf(i, n) == 1:
                coprimes.append(i)
            if len(coprimes) > max and max:
                return coprimes
        return coprimes

    def prime(self, n, primes):
        for p in primes:
            if n % p == 0:
                return False
        return True

    def get_large_primes(self, lower, upper, verbose=False):
        primes = self.sieve(int(math.sqrt(upper)))
        primes_found, nums_tried = [], []
        while len(primes_found) != 2:
            num = random.randint(lower, upper)
            if self.prime(num, primes) and num not in nums_tried:
                primes_found.append(num)
        return primes_found

    def powmod(self, n, e, mod):
        original = n
        n = 1
        for i in range(e):
            n = (n * original) % mod
        return n

    def get_coefficients(self, p, q):
        n = p * q
        t = (p - 1) * (q - 1)
        e = self.get_coprimes(t, max=10)[1]
        d = 1
        while True:
            if (d * e % t) == 1:
                return d, e
            d += 1

    def create_charmaps(self, coprimes):
        coprimes = coprimes[1:-1]
        int2char = {coprimes[i]: c for i, c in enumerate(self.chars)}
        char2int = {c: coprimes[i] for i, c in enumerate(self.chars)}
        return int2char, char2int

    def save_all(self, public_key, private_key, int2char, char2int, filename="rsa.pkl"):
        with open(filename, "wb") as f:
            pickle.dump([public_key, private_key, int2char, char2int], f)

    def load(self, filename="rsa.pkl"):
        with open(filename, "rb") as f:
            public_key, private_key, int2char, char2int = pickle.load(f)
        self.public_key, self.private_key = public_key, private_key
        self.int2char, self.char2int = int2char, char2int

    def encode(self, msg):
        return ":".join([str(self.powmod(self.char2int[char], self.public_key[1], self.public_key[0])) for char in msg])[:-1]

    def decode(self, msg):
        return "".join([self.int2char[self.powmod(int(n), self.private_key, self.public_key[0])] for n in msg.split(":")])

    def create_keys(self, lower, upper, save_new=True, verbose=False):
        p, q = self.get_large_primes(lower, upper)
        assert (p - 1) * (q - 1) > len(self.chars), "Not enough coprimes to map to characters, please pick larger prime numbers"
        if verbose:
            print(f"[RSA]: Found prime numbers: p = {p}, q = {q}")
        n = p * q
        if verbose:
            print(f"[RSA]: Found product of p and q: n = {n}")
        d, e = self.get_coefficients(p, q)
        if verbose:
            print(f"[RSA]: Found coefficients: d = {d}, e = {e}")
        coprimes = self.get_coprimes(n, max=len(self.chars) + 1)
        if verbose:
            print("[RSA]: Creating character maps with coprimes of n")
        charmaps = self.create_charmaps(coprimes)
        if save_new:
            self.save_all([n, e], d, *charmaps)
            if verbose:
                print("[RSA]: Saved details to disk")
        return {"public_key": [n, e], "private_key": d, "int2char": charmaps[0], "char2int": charmaps[1]}


if __name__ == "__main__":
    rsa = RSA()
    rsa.create_keys(100, 1000, verbose=True)
    rsa.load("rsa.pkl")
    msg = rsa.encode("Hello World!")
    print(msg)
    print()
   