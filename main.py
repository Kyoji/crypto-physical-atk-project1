import math
import timeit
import decrypt
import primes
import secretKey
import experiment


################################################


experiment.runExperiment();


def decryptTest():
    print("This is a simulated decryption. It uses", c, "as a cipher encoding an unknown message m.")
    print("The output below is the decrypted m")
    print()

    start_time = timeit.default_timer()
    ma = decrypt.crt(c, key)
    ma_runtime = timeit.default_timer() - start_time
    print("CRT result:", ma)
    print()

    start_time = timeit.default_timer()
    mb = decrypt.fastExp(c, decrypt.binaryEncodeNaive(key.d), key.n)
    mb_runtime = timeit.default_timer() - start_time
    print("FastExp result:", mb)
    print()

    if ma == mb: print("CRT and FastExp results identical")

    print("CRT took", ma_runtime, "seconds")
    print("FastExp took", mb_runtime, "seconds")

    if ma_runtime < mb_runtime:
      print( "CRT faster by", mb_runtime - ma_runtime, "seconds" )
    else:
      print( "FastExp faster by", ma_runtime - mb_runtime, "seconds" )

