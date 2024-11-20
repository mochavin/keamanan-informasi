import random
import time
import threading

def gcd(a, b):
  while b:
    a, b = b, a % b
  return a

def mod_inverse(e, phi):
  for d in range(1, phi):
    if (e * d) % phi == 1:
      return d
  return None

def generate_rsa_keys():
  p = 5779
  q = 3769
  n = p * q
  phi = (p - 1) * (q - 1)
  e = random.randrange(2, phi)
  while gcd(e, phi) != 1:
    e = random.randrange(2, phi)
  d = mod_inverse(e, phi)
  public_key = (e, n)
  private_key = (d, n)
  return public_key, private_key

def encrypt_rsa(public_key, plaintext):
  e, n = public_key
  ciphertext = [pow(ord(char), e, n) for char in plaintext]
  return ciphertext

def decrypt_rsa(private_key, ciphertext):
  d, n = private_key
  plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
  return plaintext

# public_key, private_key = generate_rsa_keys()
# print("Public Key:", public_key)
# print("Private Key:", private_key)

# message = "Hello RSA!"

# encrypted_message = encrypt(public_key, message)
# print("Encrypted Message:", encrypted_message)

# decrypted_message = decrypt(private_key, encrypted_message)
# print("Decrypted Message:", decrypted_message)

