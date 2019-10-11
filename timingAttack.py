import random
import csv
import statistics
from rsa_functions import *
from timing_measurements import *
from mpmath import *

'''
Timing Attack
As described by Dan Boneh in "Twenty Years of Attacks on RSA"
Must know: bit-length of d
Must be able to: Precisely time modular multiplication and modular exponentiation
Process:
    Measure thousands of Tis on target system using random Ms and secret key
    Measure thousands of tis on target system using random Ms
    Run the decryption. For each bit of d, measure Ti = m_Ti and measure ti = m_ti.
    Use Pearson correlation to determine if m_ti & m_Ti have a correlation
        If yes, di = 1!
'''

def timingAttackBoneh(ti_file="modboneh.csv", Ti_file="modexp.csv", Mi_file="randoms.csv"):
    # Measurements for ti & Ti obtained offline
    (pk, sk, p, q) = rsa_gen_keys(True, 4096)
    ti = []
    T = []
    Mi = []
    d = sk[1]
    expectation_x = 0
    expectation_y = 0
    with open(ti_file, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            ti.append(float(row[0]))
    csvfile.close()
    with open(Ti_file, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            T.append(float(row[0]))
    csvfile.close()
    Mi = readRandomsFromFile("randoms.csv", 1)

    # Next compute stddev of ti and Ti
    ti_std = statistics.stdev(ti)
    ti_mean = statistics.mean(ti)
    Ti_std = statistics.stdev(T)
    Ti_mean = statistics.mean(T)

    Tis = [] # 1D Array
    tis = [] # 2D Array

    print("Calculating Pearson coefficients to determine a correlation between ti and Ti for the first 3 bits of d")
    print("Ideally we see -1 or 1 for a correlation, 0 for no correlation")
    for i in range(0, 2):
        T_avg = 0
        for j in range(0, 10):
            _, T, t_list = bitwise_square_multiply_timings(Mi[i], sk[1], sk[0])
            T_avg += T
            tis.append(t_list)
        Tis.append(T_avg / 10)

        # Calc pearson coeffecient for Ti, ti
        expct_x = 0
        expct_y = 0
        std_x = 0
        std_y = 0
        top = 0
        for k in range(0, len(tis)):
            expct_x += (tis[k][i] - ti_mean)
            expct_y += (Tis[i] - Ti_mean)
            std_x += expct_x**2
            std_y += expct_y**2
            top += expct_x * expct_y

        bottom = sqrt(std_x) * sqrt(std_y)
        pc = top / bottom
        print("Pearson coeffecient for t[", i, "] and T[", i, "]:")
        print(pc)
    print("No conclusions can be made")
    print("Data is too noisy, and not normally distributed")



def bit_process_time(b):
    bit_time = timeit.default_timer()
    # Check LSB
    bit = 0
    product = 1
    t_mod = 0
    t = random.getrandbits(9000)
    n = random.getrandbits(8192)
    if (b & 1) == 1:
        bit = 1
        t_mod = timeit.default_timer()
        # Multiply
        product = (product * t) % n
        t_mod = timeit.default_timer() - t_mod
    # Square
    t = (t * t) % n
    # Shift right by 1 bit
    b >>= 1
    bit_time = timeit.default_timer() - bit_time
    return bit_time, t_mod

def getVanCujikMeasures():
    test_bit_1 = []
    test_bit_0 = []
    t_mod = []
    iters = 10000
    for i in range (0, iters):
        t1, tm = bit_process_time(1)
        t0, _ = bit_process_time(0)
        t_mod.append(tm)
        test_bit_1.append(t1)
        test_bit_0.append(t0)

    test_bit_1_avg = statistics.mean(test_bit_1)
    test_bit_0_avg = statistics.mean(test_bit_0)
    t_mod_avg = statistics.mean(t_mod)
    test_bit_1_std = statistics.stdev(test_bit_1)
    test_bit_0_std = statistics.stdev(test_bit_0)
    t_mod_std = statistics.stdev(t_mod)

    #print(test_bit_1_avg, test_bit_0_avg, t_mod_avg)
    #print(test_bit_1_std, test_bit_0_std, t_mod_std)

    return test_bit_1_avg, t_mod_avg

def timingAttackVanCujik():
    print("Attempting to predict first bit using van Cujik method")
    bit1time, modtime = getVanCujikMeasures()
    #set iterations
    iters = 2
    time_list = []
    tcd_list = []
    tc_list = []
    message = "Whats up van cujik"
    mint = string_to_int(message)
    (pk, sk, p, q) = rsa_gen_keys(True, 4096)
    d = sk[1]
    n = sk[0]
    for i in range(0, iters):
        start = timeit.default_timer()
        bitwise_square_multiply(mint, d, n)
        end = timeit.default_timer() - start
        time_list.append(end)
    for j in range(0, len(time_list)):
        tcd_list.append(time_list[j] - bit1time - modtime)
        tc_list.append(time_list[j] - bit1time)
    tcd_mean = statistics.mean(tcd_list)
    tcd_std = statistics.stdev(tcd_list)
    tc_mean = statistics.mean(tc_list)
    tc_std = statistics.stdev(tc_list)
    t_mean = statistics.mean(time_list)

    prob_1 = ((t_mean - bit1time - modtime) - tcd_mean) / tcd_std
    prob_1 = normal_density(prob_1)

    prob_0 = ((t_mean - bit1time) - tc_mean) / tc_std
    prob_0 = normal_density(prob_0)

    prob_bayes = prob_1 / (prob_1 + prob_0)

    print("Probability first bit == 1:", prob_bayes)

    return
