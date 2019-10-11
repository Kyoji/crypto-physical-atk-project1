import sys
import math
from rsa_functions import *
from sm_vs_crt import *
from fault_attack import *
from timingAttack import *

sys.setrecursionlimit(10000)

# -------------------------------------------------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------------------------------------------------

print('---------------------------------------')
print('Project 1: RSA encryption/decryption \n')
print('Part A: Encryption/Decryption Speed of the Chinese Remainder Theorem vs. Fast Exponentiation')
print('---------------------------------------')
print()

message = 'please do not be alarmed'
mint = string_to_int(message)
print("Message to be encrypted:", message)
print()

print('---------------------------------------')
bits = 4096
print('Generating a private and public key from', bits, 'bit primes')
print()
(pk, sk, p, q) = rsa_gen_keys(True, bits)

print('---------------------------------------')
print('Encrypting message...')
c, enc_time = rsa_fe_encrypt(mint, pk)
print('Resulting cipher:', c)
print()

# -------------------------------------------------------------------------------------------------------------
# Static Bit Comparison
# -------------------------------------------------------------------------------------------------------------

#file_tests = 10000
#test_file_comparison_static_bit(c, sk, p, q, file_tests)

# -------------------------------------------------------------------------------------------------------------
# Increasing Bit Comparison
# -------------------------------------------------------------------------------------------------------------

#test_file_comparison_increasing_bit()

# -------------------------------------------------------------------------------------------------------------
# Runtime tests
# -------------------------------------------------------------------------------------------------------------

print('---------------------------------------')
print('Decrypting using Fast Exponentiation...')
m, fxp_time = rsa_fe_decrypt(c, sk)
print('Decrypted message:', int_to_string(m))
print('Decryption took', fxp_time, 'seconds')
print()

print('---------------------------------------')
print('Decrypting using Chinese Remainder Theorem...')
m2, crt_time = rsa_crt_decrypt(c, sk, p, q)
print('Decrypted message:', int_to_string(m2))
print('Decryption took', crt_time, 'seconds')
print()

print('---------------------------------------')
print('Decrypting using CRT with pre-calcuated values')
m3, crt_prb_time = rsa_crtprebaked_decrypt(c, sk, p, q)
print('Decrypted message:', int_to_string(m3))
print('Decryption took', crt_prb_time, 'seconds')
print()

#print('---------------------------------------')
#print('Running 10 tests using a', bits * 2,'bit N')
#f = open('results.csv', 'w')
#f.write('Iteration,Fast Exponentiation,CRT,CRT Pre-baked')
#print('Fast Exp Average (10 runs):', test_fastexp(c, sk, f))
#print('CRT Average (10 runs):', test_crt(c, sk, p, q, f))
#print('CRT Pre-baked Average (10 runs):', test_crt_prebaked(c, sk, p, q, f))
#f.close()
#print()

# -------------------------------------------------------------------------------------------------------------
# Fault Attack
# -------------------------------------------------------------------------------------------------------------


print('---------------------------------------')
print('Project 1: RSA encryption/decryption \n')
print('Part B: Demonstrating the RSA Fault Attack')
print('---------------------------------------')
print()

print('The RSA Fault Attack is based on the Chinese Remainder Theorem inplemention of the exponentiation method.')
print('It occurs when exactly one message cp or cq is corrupted whether by software/hardware fault, or by an attacker')
print('It requires a correct message m, and when executed successfully it exposes one factor of n, p or q')
print('We will focus on one case: cq becoming corrupted. Corrupted cq will be referred to as cq`')
print('Normally, cq is a number s.t. cq === cq mod p and cq === cq mod q')
print('cq` is s.t. cq` === cq mod p but cq` !== cq mod q')
print()
print('Stated in another way, cq` is s.t. p | (cq` - cq) but q !| (cq` - cq)')
print('Since q does not divide cq`, we can calcuate the gcd of the difference between it and n to find p:')
print('gcd(cq` - cq, n)')
print('The resulting number will equal p. If cp was corrupted, the resulting number will equal q')
print()
print('Demonstration')
print('We must use RSA Sign and Verify, which is RSA Decrypt and Encrypt respectively')
message = 'The fault attack is pretty cool'
mint = string_to_int(message)
print('The message to be signed is:', message)
s, _ = rsa_crt_decrypt(mint, sk, p, q)
print('The computed signature m is:')
print(s)
print('Verifying the signature gives us:')
v, _ = rsa_fe_encrypt(s, pk)
print(int_to_string(v))
print()
print('Next, we generate a corrupted message m`:')
sc, _ = rsa_crt_decrypt(mint, sk, p, q, comp_crt_exp_corrupt)
print('The computed signature m` is computed by randomly corrupting message mp or mq:')
print(sc)
print('Next, take the gcd of (m` - m, n):')
recovered_factor = math.gcd(sc - s, p*q)
print('The recovered factor is:')
print(recovered_factor)
print('Divide N by the recovered factor to recover the other factor')
recovered_factor_2 = sk[0] // recovered_factor
print('Verify we have the correct p and q by signing a new message, then verifying')
print('Signing message \"You\'ve activated my trap card\"')
new_m = "You've activated my trap card"
new_mint = string_to_int(new_m)
m, _ = rsa_crt_decrypt(new_mint, sk, recovered_factor, recovered_factor_2)
mv, _ = rsa_fe_encrypt(m, pk)
print('Verifying the signature gives us:')
print(int_to_string(mv))



# -------------------------------------------------------------------------------------------------------------
# Timing Attack
# -------------------------------------------------------------------------------------------------------------
print('---------------------------------------')
print('Project 1: RSA encryption/decryption \n')
print('Part C: Demonstrating the RSA Timing Attack')
print('---------------------------------------')
print()
timingAttackBoneh()
timingAttackVanCujik()
