import random
import math
import string
import numpy as np
import pickle
import os, sys


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

    def save(self, public_key, private_key, filename="rsa.pkl"):
        with open(filename, "wb") as f:
            pickle.dump((public_key, private_key), f)

    def load(self, filename="rsa.pkl"):
        with open(filename, "rb") as f:
            public_key, private_key = pickle.load(f)
        self.public_key, self.private_key = public_key, private_key

    def encode(self, msg):
        return ":".join([str(pow(ord(char), self.public_key[1], self.public_key[0])) for char in msg + " "])[:-1]

    def decode(self, msg):
        return "".join([chr(pow(int(n), self.private_key, self.public_key[0])) for n in msg.split(":")[:-1]])

    def create_keys(self, lower, upper, save_new=True, verbose=False):
        p, q = self.get_large_primes(lower, upper)
        if verbose:
            print(f"[RSA]: Found prime numbers: p = {p}, q = {q}")
        n = p * q
        if verbose:
            print(f"[RSA]: Found product of p and q: n = {n}")
        d, e = self.get_coefficients(p, q)
        if verbose:
            print(f"[RSA]: Found coefficients: d = {d}, e = {e}")
        if save_new:
            self.save((n, e), d)
            if verbose:
                print("[RSA]: Saved details to disk")
        return (n, e), d

    def modinv(self, a, m):
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = m, a
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        gcd, x, y = old_r, old_s, old_t
        return x % m

    def get_coefficients(self, p, q):
        mod = (p - 1) * (q - 1)
        e = self.get_coprimes(mod, max=1000)[random.randint(1, 999)]
        d = self.modinv(e, mod)
        return d, e


def main():
    rsa = RSA()
    if not os.path.exists("rsa.pkl"):
        rsa.create_keys(1e+12, 1e+15, save_new=True, verbose=True)
    rsa.load("rsa.pkl")

    data = "Hello World!"
    print("Original data:", end=" ")
    print(data)
    input("Press enter to encrypt...")
    enc = rsa.encode(data)
    print("Encrypted data:", end=" ")
    print(enc)
    input("Press enter to decrypt...")
    print("Decrypted data:", end=" ")
    print(rsa.decode(enc))

if __name__ == "__main__":
    main()

