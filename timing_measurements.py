import csv
import random
from mpmath import *
import math

mp.dps = 50
mp.pretty = True

def normal_density(x):
    top = power(math.e, (-1*(power(x, 2) / 2) ))
    bottom = sqrt(2*math.pi)
    return top / bottom

def generateFromBitRange(lower=0, upper=8192):
    return random.randrange(lower, random.getrandbits(upper))


def writeRandomsToFile(name="randoms.csv", number=100000):
    with open(name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for i in range(0, number):
            writer.writerow([generateFromBitRange()])
    csvfile.close()


def readRandomsFromFile(name="randoms.csv", columns=1, rows=-1):
    list_a = []
    list_b = []
    with open(name, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        i = 1
        for row in reader:
            if columns == 2:
                list_b.append( int(row[1]) )
                list_a.append( int(row[0]) )
            elif columns == 1 :
                list_a.append( int(row[0]) )
            if rows > -1:
                if i == rows:
                    break
                i += 1
    csvfile.close()
    if columns == 2: return (list_a, list_b)
    elif columns == 1: return list_a
    

# Test a * b mod N
def testModMulti(iters=100000):
    f = open("modmulti.csv", "w")
    (pk, sk, p, q) = rsa_gen_keys(True, 4096)
    N = sk[0]
    (a, b) = readRandomsFromFile("random_ab.csv", 2)

    for i in range(0, iters):
        time = timeit.default_timer()
        a[i] * b[i] % N
        time = timeit.default_timer() - time
        f.write("{}\n".format(time))
    f.close()

# Test M * M^2 mod N
def testModMultiCubed(iters=10000):
    f = open("modboneh.csv", "w")
    (pk, sk, p, q) = rsa_gen_keys(True, 4096)
    N = sk[1]
    d = sk[0]
    print(d.bit_length())
    a = readRandomsFromFile("randoms.csv", 1, iters)

    for i in range(0, iters):
        time = timeit.default_timer()
        a[i] * (a[i]**2 % N)
        time = timeit.default_timer() - time
        f.write("{}\n".format(time))
    f.close()

# Test full exponentiation
def testModExp(iters=10000):
    f = open("modexp.csv", "w")
    (pk, sk, p, q) = rsa_gen_keys(True, 4096)
    N = sk[0]
    d = sk[1]
    a = readRandomsFromFile("randoms.csv", 1, iters)

    for i in range(0, iters):
        time = timeit.default_timer()
        bitwise_square_multiply(a[i], d, N)
        time = timeit.default_timer() - time
        f.write("{}\n".format(time))
        print(time)
    f.close()

def test_file_comparison_static_bit(c, sk, p, q, iterations = 100000):
    f = open("comparison_static_bit.csv", "w")
    f.write("Iteration,FastExp,CRT,CRT Pre-computed\n")
    for i in range(0, iterations):
        _, fastexp = rsa_fe_decrypt(c, sk)
        _, crt = rsa_crt_decrypt(c, sk, p, q)
        _, crtpre = rsa_crtprebaked_decrypt(c, sk, p, q)
        f.write("{},{},{},{}\n".format(i, fastexp, crt, crtpre))
        if i % 1000 == 0:
            print(i)
    f.close()

def test_file_comparison_increasing_bit(iterations = 10):
    f = open("comparison_increasing_bit.csv", "w")
    f.write("Bit Length,Square and Multiply,Chinese Remainder Theorem,CRT With Pre-computed Values\n")
    for i in range(1, 9):
        fe_avg = 0
        crt_avg = 0
        crtpb_avg = 0
        bit_depth = 512 * i
        message = 'please do not be alarmed'
        mint = string_to_int(message)
        print("Generating", bit_depth, "bit primes...")
        (pk, sk, p, q) = rsa_gen_keys(False, bit_depth)
        c, _ = rsa_fe_encrypt(mint, pk)
        print("Running tests...")
        fe_avg += test_fastexp(c, sk, iterations)
        crt_avg += test_crt(c, sk, p, q, iterations)
        crtpb_avg += test_crt_prebaked(c, sk, p, q, iterations)
        f.write("{},{},{},{}\n".format(bit_depth, fe_avg, crt_avg, crtpb_avg))
    f.close()