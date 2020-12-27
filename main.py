import sha256
import elliptic
import shark

# Order (?):
# INPUT -> HASH -> ENCRYPT -> SEND TO PAYMENT AUTHENTICATION SERVER -> DECRYPT -> COMPARE SHA-256 VALUES

# TITLE:
# Secure payment with server identification
# using Elliptic protocol signature and key exchange,
# encryption-decryption with SHARK checking with SHA-256.

# server identification
def payment(id, credit):
    # SHA256 HASHING
    print(sha256.sha_256(credit))

    # ELLIPTIC CURVE
    a, b, q = 1, 18, 19
    ec = elliptic.EC(a, b, q)

    #for i in range(19):
    #    try:
    #        g, _g = ec.at(i)
    #        print(g, _g)
    #    except:
    #        #print("No solution for", i ,"on curve. Please select another x-point.")
    #        pass

    g, _g = ec.at(8)
    original_g = g
    for i in range(q - 1):
        g = elliptic.EC.mul(ec, g, i + 1)
        print(g)
        g = original_g

def main():
    payment("319151213", "4580120779488793")

main()