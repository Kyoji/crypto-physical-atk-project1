import decrypt
import primes

class SecretKey(object):
    """Contains all components of a secret key"""
    n = 0
    d = 0
    dp = 0
    dq = 0
    qinv = 0
    e = 0
    # Pre-compute all of the components typically found in a private key
    # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
    def compPrivateKeyComponents(self):
      self.n = self.p*self.q
      self.d = decrypt.modinv(self.e, decrypt.lcm(self.p - 1, self.q - 1)) # Generate the secret key from p and q
      self.dp = pow(self.d, 1, self.p - 1) # Fermat's Little Theorem
      self.dq = pow(self.d, 1, self.q - 1) # Fermat's Little Theorem
      self.qinv = decrypt.modinvprime(self.q, self.p)

      #return (n, d, dp, dq, qinv)

    def refresh(self):
        self.p = primes.generate_prime_number()
        self.q = primes.generate_prime_number()
        self.compPrivateKeyComponents()

    def __init__(self):
        self.e = 65537 # This is apparently a typical constant for RSA
        self.refresh()