import secrets
import math
import base64
from Crypto.Cipher import AES

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


# Gera a chave publica 'n' e o totiente de n
def n_public_key_and_totient(p, q):
    return p * q, (p - 1) * (q - 1)


# Retorna se dois numeros sao coprimos ou nao
def coprime(a, b):

    if math.gcd(a, b) == 1:
        return True
    else:
        return False


# Gera a segunda chave publica 'e' a partir do totiente
def generate_e(totient):
    while True:
        e = randomNumberGenerator.randrange(2, totient)
        if coprime(e, totient):
            return e


# Gera o inverso multiplicativo de 'e' de acordo com o totiente de 'n' // CHAVE PRIVADA
def multiplicative_inverse(e, totient):
    return pow(e, -1, totient)


def RSA_cipher(data):
    result = ""
    bits = 1024
    p = generate_prime(bits)  # CHAVE PRIVADA
    while True:
        q = generate_prime(bits)  # CHAVE PRIVADA
        if q != p:
            break

    n, totient = n_public_key_and_totient(p, q)  # CHAVE PUBLICA
    e = generate_e(totient)  # CHAVE PUBLICA

    d = multiplicative_inverse(e, totient)  # CHAVE PRIVADA

    data_bytes = data.encode("ascii")
    for byte in data_bytes:
        ciphered_byte = pow(byte, d, n)
        result += " " + str(ciphered_byte)

    print("cifradp: ", result)
    return result, n, e, p, q, d

    # base64_bytes = base64.b64encode()


def RSA_decipher(numeric_data, public_key_e, public_key_n):
    result = ""

    if not numeric_data or not public_key_e or not public_key_n:
        numeric_data = input("Insira o dado em formato numérico: ")
        public_key_e = input("Insira a chave publica E: ")
        public_key_n = input("Insira a chave publica N: ")

    arrayOfNumbers = numeric_data.split()

    for number in arrayOfNumbers:
        number = int(number)
        deciphered_byte = pow(number, public_key_e, public_key_n)
        character = chr(deciphered_byte)
        result += character

    print("Resultado: ", result)


def AES_cipher(data, AES_key):
    cipher = AES.new(AES_key, AES.MODE_CTR)

    nonce = cipher.nonce

    ciphertext = cipher.encrypt(data)
    hash = cipher.digest();
    print(ciphertext, hash)
    return ciphertext, nonce, hash

def AES_decipher(ciphertext, AES_key, nonce, hash):
    cipher = AES.new(AES_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(hash)
        print("Texto em claro: ", plaintext)
    except ValueError:
        print("Chave incorreta ou mensagem corrompida")

# print(randomBits, miller_rabin(randomBits))
# print(generate_e(4309534058743086459645906845906808))
# (
#     result,
#     public_keyN,
#     public_keyE,
#     private_keyP,
#     private_keyQ,
#     private_keyD,
# ) = RSA_cipher("arroz doce quente azul vermelhooooooooorosa+!@#")
# print(
#     "Inputs decipher: ",
#     public_keyE,
#     public_keyN,
#     " P e Q: ",
#     private_keyP,
#     private_keyQ,
# )
# RSA_decipher(result, public_keyE, public_keyN)
AES_key = secrets.randbits(128)
AES_key = AES_key.to_bytes(16, "big")
ciphertext, nonce, hash = AES_cipher("rosaaaana ao senhooooor", AES_key)
AES_decipher( ciphertext, AES_key, nonce, hash)
