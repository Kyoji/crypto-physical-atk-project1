
import decrypt
import timeit
from secretKey import SecretKey


def experimentSetup():
    return

def runExperiment(iterations=10):
    exp_runtime = timeit.default_timer()
    c = 1234567890
    key = SecretKey()
    crt_runtime = 0
    fastexp_runtime = 0

    F = open("results.csv", "w")
    F.write("Iteration,CRT Time,FastExp Time\n")
    
    for i in range (1, iterations+1):
        print(i)
        if i % (101) == 0:
            key.refresh()
        crt_runtime = runCRT(c, key)
        fastexp_runtime = runFastExp(c, key)
        F.write('{},{},{}\n'.format(i, crt_runtime, fastexp_runtime))

    exp_runtime = timeit.default_timer() - exp_runtime
    F.close()
    print("Experiment finished at", exp_runtime, "seconds")

def runCRT(c, key):
    crt_runtime = timeit.default_timer()
    decrypt.crt(c, key)
    return timeit.default_timer() - crt_runtime

def runFastExp(c, key):
    fastexp_runtime = timeit.default_timer()
    decrypt.fastExp(c, decrypt.binaryEncodeNaive(key.d), key.n)
    return timeit.default_timer() - fastexp_runtime

