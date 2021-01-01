# Elliptic Curve Implementation

import collections

Coord = collections.namedtuple("Coord", ["x", "y"])


def inv(n, q):
    """Find the inverse on n modulus q """
    return egcd(n, q)[0] % q


def egcd(a, b):
    """extended GCD according to euclid's algorithm
    finds (s, t) such that a*s + b*t == gcd
    """
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
    return s0, t0, a


class EC(object):
    def __init__(self, a, b, q, G, order):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 <= a and a < q and 0 <= b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2)) % q != 0
        self.a = a                  # Coefficient of x
        self.b = b                  # Constant term
        self.q = q                  # Large prime number
        self.G = G                  # Generator point / Base point
        self.zero = Coord(0, 0)     # Zero point

        # Order -
        # An elliptic curve defined over a finite field has a finite number of points.
        # The number of points in a group is called the order of the group.
        self.order = order

    def add(self, p1: Coord, p2: Coord):
        """This function returns the addition of two points on the elliptic curve"""
        if p1 == self.zero:
            return p2
        if p2 == self.zero:
            return p1
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
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """This function returns the nth multiplication of a point on the elliptic curve"""
        r = self.zero
        m2 = p

        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        return r
