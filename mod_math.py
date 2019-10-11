import math

# https://www.geeksforgeeks.org/weak-rsa-decryption-chinese-remainder-theorem/
# TODO: implement my own loop version
def egcd(e, phi):
    if e == 0:
        return (phi, 0, 1)
    else:

        g, y, x = egcd(phi % e, e)
        return (g, x - (phi // e) * y, y)

# https://www.geeksforgeeks.org/weak-rsa-decryption-chinese-remainder-theorem/
# The modular multiplicative inverse is an integer x s.t.
# e(x) mod phi == 1 mod phi
def modinv(e, phi):
    _, x, _ = egcd(e, phi)
    return x % phi

# p and q are always prime
# we can use fermat's little theorem to optimize
# using flt: let m be prime. a^m-2 mod m = a^-1 mod m
def modinvprime(a, m):
    return pow(a, m-2, m) if math.gcd(a, m) == 1 else print("p or q not prime")

# https://www.geeksforgeeks.org/weak-rsa-decryption-chinese-remainder-theorem/
def lcm(p, q):
    return p * q // math.gcd(p, q)
