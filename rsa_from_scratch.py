import random
import sympy

def generate_prime(bits=512):
    return sympy.randprime(2**(bits-1), 2**bits)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(bits=512):
    p, q = generate_prime(bits), generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = modinv(e, phi)
    return (e, n), (d, n)

def encrypt(message, pubkey):
    e, n = pubkey
    return [pow(ord(char), e, n) for char in message]

def decrypt(ciphertext, privkey):
    d, n = privkey
    return ''.join(chr(pow(char, d, n)) for char in ciphertext)

# Генерация ключей
public_key, private_key = generate_keys()

# Шифрование
message = "Hello, RSA!"
ciphertext = encrypt(message, public_key)
print("Encrypted:", ciphertext)

# Дешифрование
decrypted_message = decrypt(ciphertext, private_key)
print("Decrypted:", decrypted_message)

