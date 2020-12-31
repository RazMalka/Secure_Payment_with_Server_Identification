# Elliptic Curve Implementation

import collections

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q """
    return egcd(n, q)[0] % q

def egcd(a, b):
    """extended GCD
    returns: (s, t, gcd) as a*s + b*t == gcd
    """
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a

def sqrt(ysq, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist"""
    assert ysq < q
    for i in range(1, q):
        if i * i % q == ysq:
            return (i, q - i)
        pass
    raise Exception("not found")

Coord = collections.namedtuple("Coord", ["x", "y"])

class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q, G, order):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 <= a and a < q and 0 <= b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        self.G = G
        self.zero = Coord(0, 0)
        self.order = order
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: int < q
        - returns: ((x, y), (x,-y)) or not found exception
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p"""
        return Coord(p.x, -p.y % self.q)

    def add(self, p1:Coord, p2:Coord):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line"""
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            temp1 = (p2.y - p1.y)
            temp2 = inv(p2.x - p1.x, self.q)
            l = temp1 * temp2 % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve"""
        r = self.zero
        m2 = p

        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        return r

    def _order(self, g):
        """order of point g"""
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            pass
        raise Exception("Invalid order")
    pass