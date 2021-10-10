import secrets
import math

randomNumberGenerator = secrets.SystemRandom()

randomBits = secrets.randbits(1024)


def miller_rabin_test(n, a):

    exp = n - 1  # expoente de a no comeco eh n-1
    while not exp & 1:  # numero impares possuem o ultimo bit a direita igual a 1
        exp >>= 1  # expoente dividido por 2 ate ser impar

    if (
        pow(a, exp, n) == 1
    ):  # se a^exp eh divisivel por n, entao (a^exp) - 1 eh divisivel por n, logo, n deve ser primo
        return True

    while (
        exp < n - 1
    ):  # enquanto o expoente for menor que n-1 (estamos checando os outros fatores de (a^exp) - 1
        if pow(a, exp, n) == n - 1:
            return True
        exp <<= 1

    return False


def miller_rabin(n, k=40):
    for i in range(k):
        a = randomNumberGenerator.randrange(2, n - 1)
        if not miller_rabin_test(n, a):
            return False

    return True


def generate_prime(bits):
    while True:
        a = (
            randomNumberGenerator.randrange(1 << bits - 2, 1 << bits - 1) << 1
        ) + 1  # Gera um numero impar
        if miller_rabin(a):
            return a


def n_public_key_and_totient(p, q):
    return p * q, (p - 1) * (q - 1)


def generate_e(totient):

    while True:
        e = randomNumberGenerator.randrange(1, totient)
        if coprime(e, totient):
            return e


def __gcd(a, b):

    # Everything divides 0
    if a == 0 or b == 0:
        return 0

    # base case
    if a == b:
        return a

    # a is greater
    if a > b:
        return __gcd(a - b, b)

    return __gcd(a, b - a)


# Function to check and print if
# two numbers are co-prime or not
def coprime(a, b):

    if math.gcd(a, b) == 1:
        return True
    else:
        return False


# print(randomBits, miller_rabin(randomBits))
print(generate_e(4309534058743086459645906845906808))
