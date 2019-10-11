import random
from rsa_functions import *

# Faulty CRT Exponentiation
# Used to simulate the Fault Attack
# One cp or cq is modified
def comp_crt_exp_corrupt( cs, ds, ns ):
    p = 0
    q = 1
    # Choose cp or cq to be corrupted
    corrupt = random.randrange(0,2)
    cs = [ cs[p], cs[q] ]
    # Corrupt
    cs[corrupt] = cs[corrupt] ^ random.randrange(cs[corrupt].bit_length())
    cp = bitwise_square_multiply(cs[p], ds[p], ns[p])
    cq = bitwise_square_multiply(cs[q], ds[q], ns[q])
    return (cp, cq)