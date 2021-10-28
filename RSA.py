# ======================================================================================================================================#
#      Nome: 				RSA.py                                                                                                      #
#      Descricao: 			Simula um remetente e um destinatario de mensagens criptografadas usando RSA-OAEP, AES-128-CTR e SHA3-512   #
#      Autor: 				Thiaggo Ferreira Bispo de Souza                       											            #
#      Data de criacao: 		10/10/2021                                                                                              #
#      Data de atualizacao: 	27/10/2021                                                                                              #
# ======================================================================================================================================#


import os
import secrets
import math
import base64
import hashlib
from Crypto.Cipher import AES


randomNumberGenerator = secrets.SystemRandom()  # Gerador numeros aleatorios

randomBits = secrets.randbits(1024)  # Gerar 1024 bits aleatorios


# Faz o teste de miller-rabin // Recebe um inteiro 'n' e um inteiro 'a' e retorna se 'a' eh primo ou nao
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


# Funcao que gera um numero 'a' e faz o teste de miller-rabin // Recebe um inteiro 'n' para delimitar e pode receber um 'k' que define o numero de vezes que o teste sera feito
def miller_rabin(n, k=40):
    for i in range(k):
        a = randomNumberGenerator.randrange(2, n - 1)
        if not miller_rabin_test(n, a):
            return False

    return True


# Gera um numero primo de tamanho 'bits'
def generate_prime(bits):

    while True:
        prime_candidate = (
            randomNumberGenerator.randrange(math.sqrt(2) * 2 ** (bits - 1), 2 ** bits)
            | 1
        )  # Gera um numero impar
        if miller_rabin(prime_candidate):
            return prime_candidate


# Gera a chave publica 'n' e o totiente de n // Recebe p e q, dois primos
def n_public_key_and_totient(p, q):
    return p * q, (p - 1) * (q - 1)


# Retorna se dois numeros 'a' e 'b' sao coprimos ou nao
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


# Gera o inverso multiplicativo de 'e' de acordo com o totiente de 'n' // Recebe o valor da chave privada 'e' e o totiente de 'n e retorna o inverso multiplicativo de 'e'
def multiplicative_inverse(e, totient):
    return pow(e, -1, totient)


# Gera as chaves do RSA
def RSA_key_generation():
    bits = 1024
    private_key_p = generate_prime(bits)  # CHAVE PRIVADA

    while True:
        private_key_q = generate_prime(bits)  # CHAVE PRIVADA
        if private_key_q != private_key_p:
            break

    public_key_n, totient = n_public_key_and_totient(
        private_key_p, private_key_q
    )  # CHAVE PUBLICA

    public_key_e = generate_e(totient)  # CHAVE PUBLICA

    private_key_d = multiplicative_inverse(
        public_key_e, totient
    )  # CHAVE PRIVADA (usada)

    # Como 'n' eh sempre necessario, ele esta sempre incluso nas chaves privada e publica
    public_key = public_key_e, public_key_n
    private_key = private_key_d, public_key_n

    return public_key, private_key


# Converte um inteiro para uma string de bytes de tamanho x_len // Recebe um dado em inteiro e um numero de bytes e retorna um dado em bytes
def i2osp(x, x_len):
    return x.to_bytes(x_len, "big")


# Converte uma string de bytes para um inteiro  // Recebe um dado em bytes e retorna um dado em inteiro, big endian
def os2ip(byte_string):
    return int.from_bytes(byte_string, "big")


# Faz o XOR entre o dado e uma mascara, ou seja, mascara o dado // Recebe um dado em bytes e uma mascara em bytes e retorna um dado mascarado em bytes
def mask_data(data, mask):
    assert len(data) == len(mask)
    masked_data = b""
    for d, m in zip(data, mask):
        masked_data += i2osp(d ^ m, 1)
    return masked_data


# Funcao geradora de mascara  // Recebe um dado em bytes e o tamanho da mascara e retorna uma mascara em bytes
def MGF1(data_bytes, mask_length):
    mask = b""
    hash_length = 32
    full_blocks = math.ceil(mask_length / hash_length)
    for i in range(full_blocks):
        byte_count = i2osp(i, 4)
        mask += hashlib.sha256(data_bytes + byte_count).digest()

    return mask[:mask_length]


# Funcao que aplica o OAEP // recebe o dado em bytes e o tamanho da mensagem, 'k' - mensagem deve ter o formato (seed + data_block) - retorna um dado em inteiro
def OAEP(data_bytes, k):

    message_length = len(data_bytes)

    lHash = hashlib.sha256(b"").digest()  # label hash
    hash_length = len(lHash)

    padded_message_max_length = k - 2 * hash_length - 2
    assert (
        message_length <= padded_message_max_length
    )  # tamanho do mensagem deve ser menor ou igual ao tamanho de k - 2* tamanho do hash - 2 pois eh o tamanho que falta para atingir k bits sem contar o padding
    seed = secrets.token_bytes(hash_length)

    padding_length = (
        padded_message_max_length - message_length
    )  # tamanho do padding de acordo com o tamanho da mensagem
    padding_string = b"\x00" * padding_length

    data_block = lHash + padding_string + b"\x01" + data_bytes
    assert len(data_block) + hash_length + 1 == k

    data_block_mask = MGF1(seed, len(data_block))  # Gera a mascara para o data block
    masked_data_block = mask_data(data_block, data_block_mask)  # Mascara o data block

    seed_mask = MGF1(masked_data_block, hash_length)  # Gera a mascara para a seed
    masked_seed = mask_data(seed, seed_mask)  # Mascara a seed

    encoded_message = (
        b"\x00" + masked_seed + masked_data_block
    )  # formato byte 00 + masked_seed + masked_data_block (por isso o tamanho do data_block eh k - hash_length - 1)

    assert len(encoded_message) == k

    data_integer = os2ip(encoded_message)  # Converte o dado em inteiro

    return data_integer


# Funcao que cifra em RSA OAEP  // Recebe um dado em bytes e uma chave utilizada na cifracao (pode ser tanto publica quanto privada) e retorna um dado cifrado em bytes
def RSA_OAEP_cipher(data, signature_key):

    cipher_key, public_key_n = signature_key

    k = public_key_n.bit_length() // 8

    data_integer = OAEP(data, k)

    integer_ciphered_data = pow(data_integer, cipher_key, public_key_n)

    encoded_message = i2osp(integer_ciphered_data, k)

    return encoded_message


# Funcao que decifra em RSA OAEP // Recebe o dado cifrado em bytes e a chave utilizada na decifracao e retorna o dado decifrado em bytes
def RSA_OAEP_decipher(
    ciphered_data,
    decipher_keys,
):
    decipher_key, public_key_n = decipher_keys
    k = public_key_n.bit_length() // 8

    if not ciphered_data or not decipher_key or not public_key_n:
        ciphered_data = input("Insira o dado: ")
        decipher_key = input("Insira a chave utilizada para decifracao: ")
        public_key_n = input("Insira a chave publica N: ")

    integer_ciphered_data = os2ip(ciphered_data)

    integer_deciphered_data = pow(integer_ciphered_data, decipher_key, public_key_n)

    data = OAEP_decipher(integer_deciphered_data, k)

    print("Dados decifrados: ", base64string(data), "\n")
    return data


# Funcao que faz a decifracao do OAEP // Recebe o dado em inteiro e o tamanho da mensagem, 'k' - mensagem deve ter o formato (seed + data_block) - retorna um dado em bytes
def OAEP_decipher(integer_deciphered_data, k):
    hash_length = 32

    encoded_message = i2osp(integer_deciphered_data, k)

    masked_seed = encoded_message[1 : 1 + hash_length]
    masked_data_block = encoded_message[1 + hash_length :]

    seed_mask = MGF1(masked_data_block, hash_length)
    seed = mask_data(masked_seed, seed_mask)

    data_block_mask = MGF1(seed, len(masked_data_block))
    data_block = mask_data(masked_data_block, data_block_mask)
    deciphered_lHash = data_block[:hash_length]

    expected_lHash = hashlib.sha256(b"").digest()  # label hash
    assert expected_lHash == deciphered_lHash

    index = hash_length
    while index < len(data_block):
        if data_block[index] == 0:
            index += 1
            continue
        elif data_block[index] == 1:
            index += 1
            break
        else:
            raise Exception("Padding Error")

    data = data_block[index:]
    return data


# Faz a cifracao do AES // Recebe um dado em bytes e uma chave de 128 bits e retorna um dado cifrado em bytes
def AES_cipher(data, AES_key):
    cipher = AES.new(AES_key, AES.MODE_CTR)

    nonce = cipher.nonce  # tamanho 8 bytes

    ciphertext = cipher.encrypt(data)
    too_big = len(base64string(ciphertext)) > 500
    if not too_big:
        print("Cifrado: ", base64string(ciphertext), "\n")

    print("Nonce: ", base64string(nonce), "\n")

    result = nonce + ciphertext

    return result


# Faz a decifracao do AES   // Recebe o dado cifrado e a chave AES
def AES_decipher(ciphertext, AES_key):

    nonce_length = 8
    nonce = ciphertext[:nonce_length]

    cipher = AES.new(AES_key, AES.MODE_CTR, nonce=nonce)

    try:
        plaintext = cipher.decrypt(ciphertext[nonce_length:])
        return plaintext

    except ValueError:
        print("Chave incorreta ou mensagem corrompida")


# Gerar chave de 128 bits
def generate_key():
    return secrets.token_bytes(16)


# Pega um dado em bytes e retorna um dado em string na base 64
def base64string(data):
    return base64.b64encode(data).decode("utf-8")


# Abre um arquivo para leitura e retorna o seu conteudo em bytes   // Recebe o nome de um arquivo
def read_file(file_name):
    with open(file_name, "rb") as file:
        data = file.read()
    return data


# Escreve um dado em um arquivo // Recebe o nome de um arquivo e o dado em bytes
def write_file(file_name, data):
    with open(file_name, "wb") as file:
        file.write(data)


# Funcao do remetente   // recebe 'sender_private_key' a chave privada do remetente e 'receiver_public_key' a chave publica do destinatario
def sender(data_bytes, sender_private_key, receiver_public_key):

    if not data_bytes:
        data = input("Insira a sua mensagem: ")
        data_bytes = data.encode("utf-8")  # converte a string para bytes

    too_big = len(base64string(data_bytes)) > 500

    if not too_big:
        print("Dado: ", base64string(data_bytes), "\n")

    print("Gerando chave para o AES... \n")
    key = generate_key()
    print("Chave: ", base64string(key), "\n")

    print("Distribuindo chave... \n")
    ciphered_AES_key = RSA_OAEP_cipher(key, receiver_public_key)

    print("Criando hash da mensagem... \n")
    hash_object = hashlib.sha3_512(data_bytes)  # faz o objeto hash da string
    message_digest = hash_object.digest()  # pega o hash em bytes
    if not too_big:
        print("Hash: ", base64string(message_digest), "\n")  # printa o hash em base 64

    digitally_signed_digest = RSA_OAEP_cipher(message_digest, sender_private_key)
    if not too_big:
        print("Assinatura digital: ", base64string(digitally_signed_digest), "\n")

    print("Cifrando mensagem... \n")
    ciphertext = AES_cipher(data_bytes, key)

    if not too_big:
        print("Mensagem cifrada: ", base64string(ciphertext), "\n")

    print("Criando dados para envio... \n")
    result = base64.b64encode(digitally_signed_digest + ciphertext)
    if not too_big:
        print("Dado de envio: ", result.decode("utf-8"), "\n")
    print("Enviando dado... \n")

    return (result, ciphered_AES_key)


# Funcao do destinatario // recebe 'data' o dado a ser cifrado, 'ciphered_AES_key' a chave cifrada para o AES, 'sender_public_key' a chave publica do remetente e 'receiver_private_key' a chave privada do destinatario
def receiver(data, ciphered_AES_key, sender_public_key, receiver_private_key):
    too_big = len(base64string(data)) > 500

    received_data = base64.b64decode(data)

    digitally_signed_digest_length = 256
    digitally_signed_digest = received_data[:digitally_signed_digest_length]

    ciphertext = received_data[digitally_signed_digest_length:]

    if not too_big:
        print("Dado recebido: ", base64string(received_data), "\n")
        print("Assinatura: ", base64string(digitally_signed_digest), "\n")
        print("Texto cifrado: ", base64string(ciphertext), "\n")

    print("Decifrando chave... \n")

    key = RSA_OAEP_decipher(ciphered_AES_key, receiver_private_key)
    # print("Chave: ", base64string(key), "\n")

    print("Decifrando mensagem... \n")
    plaintext_bytes = AES_decipher(ciphertext, key)

    print("Gerando hash da mensagem... \n")
    hash_object = hashlib.sha3_512(
        plaintext_bytes
    )  # faz o objeto hash dos bytes da mensagem

    generated_digest = hash_object.digest()  # pega o hash em bytes
    if not too_big:
        print(
            "Hash gerado a partir da mensagem recebida: ",
            base64string(generated_digest),
            "\n",
        )

    print("Decifrando assinatura... \n")
    received_digest = RSA_OAEP_decipher(digitally_signed_digest, sender_public_key)
    if not too_big:
        print("Hash recebido: ", base64string(received_digest), "\n")

    if generated_digest == received_digest:
        print("Integridade da mensagem assegurada!!! \n")
        try:
            plaintext = plaintext_bytes.decode("utf-8")
            print("Texto em claro: ", plaintext)
        except UnicodeDecodeError:
            option = ""
            while option == "" or option not in ["1", "2"]:
                print("O Arquivo nao eh um texto.\n")
                print("Deseja imprimir os bytes do arquivo na tela? \n")
                print("1 - Sim \n")
                print("2 - Nao \n")
                option = input("Escolha uma opcao: ")
                print("\n")
            if option == "1":
                print("Bytes: ", plaintext_bytes)

        return plaintext_bytes
    else:
        raise Exception("A mensagem foi corrompida!!! \n")


# Abrir um arquivo // Recebe o nome do arquivo
def startfile(file_name):
    try:
        os.startfile(file_name)
    except AttributeError:
        os.system("open " + file_name)


# Funcao que coordena o funcionamento do programa
def main():

    print("\n")
    file_name = input("Nome do arquivo (com extensao): ")
    data = read_file(file_name)

    output_encrypted_file_name = input("Nome do arquivo de saída (com extensao): ")
    print("\n")

    print("Gerando chaves RSA... \n")

    (
        sender_public_key,
        sender_private_key,
    ) = RSA_key_generation()
    (
        receiver_public_key,
        receiver_private_key,
    ) = RSA_key_generation()

    sender_data, AES_key = sender(data, sender_private_key, receiver_public_key)
    write_file(output_encrypted_file_name, sender_data)

    sender_encrypted_data = read_file(output_encrypted_file_name)
    plaintext_bytes = receiver(
        sender_encrypted_data, AES_key, sender_public_key, receiver_private_key
    )
    plaintext_file_name = "deciphered-" + output_encrypted_file_name

    print("Nome do arquivo de saida:", plaintext_file_name, "\n")

    write_file(plaintext_file_name, plaintext_bytes)

    startfile(plaintext_file_name)


main()
