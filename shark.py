# SHARK Implementation

def nearestPow2(x):
    x = x - 1
    x = x | (x>>1)
    x = x | (x>>2)
    x = x | (x>>4)
    x = x | (x>>8)
    x = x | (x>>16)
    x = x | (x>>32)
    x = x + 1
    if x < 1<<7:
        x = 1<<7
    return x

def encrypt():
    pass

def decrypt():
    pass