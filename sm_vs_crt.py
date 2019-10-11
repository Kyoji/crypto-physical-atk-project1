import timeit
from rsa_functions import *

# Encrypt using fast exponentiation
def rsa_fe_encrypt(m, pk):
    start = timeit.default_timer()
    (n, e) = pk
    c = bitwise_square_multiply(m, e, n)
    end = timeit.default_timer() - start
    return c, end

# Decrypt using fast exponentiation
def rsa_fe_decrypt(c, sk):
    start = timeit.default_timer()
    (n, d) = sk
    m = bitwise_square_multiply(c, d, n)
    end = timeit.default_timer() - start
    return m, end

# Decrypt using CRT
def rsa_crt_decrypt(c, sk, p, q, exp=comp_crt_exp):
    start = timeit.default_timer()
    (n, d) = sk
    m = crt_exp(c, d, p, q, exp)
    end = timeit.default_timer() - start
    return m, end

def rsa_crtprebaked_decrypt(c, sk, p, q):
    (n, d) = sk
    (dp, dq) = d % (p - 1), d % (q - 1)
    qinv = mod_math.modinv(q, p)
    start = timeit.default_timer()
    m = crt_exp_prebaked(c, p, q, dp, dq, qinv)
    end = timeit.default_timer() - start
    return m, end

def test_fastexp(c, sk, iterations=10):
    avg = 0
    for i in range(0, iterations):
        _, time = rsa_fe_decrypt(c, sk)
        avg += time
    avg = avg / iterations
    return avg

def test_crt(c, sk, p, q, iterations=10):
    avg = 0
    for i in range(0, iterations):
        _, time = rsa_crt_decrypt(c, sk, p, q)
        avg += time
    avg = avg / iterations
    return avg

def test_crt_prebaked(c, sk, p, q, iterations=10):
    avg = 0
    for i in range(0, iterations):
        _, time = rsa_crtprebaked_decrypt(c, sk, p, q)
        avg += time
    avg = avg / iterations
    return avg