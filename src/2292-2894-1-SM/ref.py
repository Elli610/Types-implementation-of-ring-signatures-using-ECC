import os, hashlib, random, Crypto.PublicKey.RSA
import sys
from functools import reduce

class ring:
    def __init__(self, k, L=1024):
        self.k = k
        self.l = L
        self.n = len(list(k))
        self.q = 1 << (L - 1)

    def sign(self, m, z):
        self.permut(m)
        s = [None] * self.n
        u = random.randint(0, self.q)
        c = v = self.E(u) 
        for i in (list(range(z+1, self.n)) + list(range(z))):
            s[i] = random.randint(0, self.q)
            e = self.g(s[i], self.k[i].e, self.k[i].n)
            v = self.E(v^e) 
            if (i+1) % self.n == 0:
                c = v
        s[z] = self.g(v^u, self.k[z].d, self.k[z].n)
        return [c] + s

    def verify(self, m, X):
        self.permut(m)
        def _f(i):
            return self.g(X[i+1], self.k[i].e, self.k[i].n)
        y = list(map(_f, list(range(len(X)-1))))
        def _g(x, i):
            return self.E(x^y[i])
        r = reduce(_g, list(range(self.n)), X[0])
        return r == X[0]

    def permut(self, m):
        self.p = int(hashlib.sha1(m.encode()).hexdigest(),16)
   #     sha1(s.encode(encoding)).hexdigest()

    def E(self, x): 
        msg = '%s%s' % (x, self.p)
        return  int(hashlib.sha1(msg.encode()).hexdigest(),16)

    def g(self, x, e, n):
        q, r = divmod(x, n)
        if ((q + 1) * n) <= ((1 << self.l) - 1):
            rslt = q * n + pow(r, e, n)
        else:
            rslt = x
        return rslt

size = 4
msg1="Hello"




def _rn(_):
  return Crypto.PublicKey.RSA.generate(1024, os.urandom)

print(("Message is:",msg1))
key = list(map(_rn, list(range(size))))
r = ring(key)
for i in range(size):
    s1 = r.sign(msg1, i)
#    s2 = r.sign(msg2, i)
    if (i==1):
      print(("Signature is", s1))
      print(("Signature verified:",r.verify(msg1, s1)))
#    assert r.verify(msg1, s1) and r.verify(msg2, s2) and not r.verify(msg1, s2)
