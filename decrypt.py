
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
    g, x, y = egcd(e, phi) 
    return x % phi 

# p and q are always prime
# we can use fermat's little theorem to optimize
# using flt: let m be prime. a^m-2 mod m = a^-1 mod m
def modinvprime(a, m):
  if math.gcd(a, m) != 1:
    print("p or q not prime")
    return
  
  return pow(a, m - 2, m)

# https://www.geeksforgeeks.org/weak-rsa-decryption-chinese-remainder-theorem/
def lcm(p, q): 
    return p * q // math.gcd(p, q)

def binaryEncodeNaive(n):
  if n == 0: return [0]
  bits = []
  while( n != 0 ):
    r = n // 2
    bit = n-(r*2)
    bits.append(bit)
    n = r
  bits = bits[::-1]
  return bits

# x to the a mod N
def fastExp( x, a, N):
  ans = []
  n = len(a)
  product = 0
  ans.append(x % N);  # Base case
  product = ans[0]    #
  for i in range(1, n):
    ans.append(ans[i-1] * ans[i-1] % N)
    # Bits are appended to ans[] backwards
    # Step through 'a[]' from lsf to gsf ('a[n-1-i]')
    # and if a '1' is found, increase the order of 'product'
    # In this manner only significant digits increase the order
    if a[n-1-i] == 1:
      product = product * ans[i] % N

  # Each iteration of the loop represents one succesive order of 2. 2^0, 2^1, etc.
  return product % N

def crt(c, key):
  # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
  # https://crypto.stackexchange.com/questions/2575/chinese-remainder-theorem-and-rsa
  m1 = pow(c, key.dp, key.p)
  m2 = pow(c, key.dq, key.q)
  h = (key.qinv  * (m1 - m2)) % key.p 
  m = m2 + (h*key.q)
  return m
