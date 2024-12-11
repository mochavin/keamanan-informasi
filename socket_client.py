import socket
import ast
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import encrypt_rsa, generate_rsa_keys, decrypt_rsa
import random
import time
from time import sleep

def client_program():
    host = socket.gethostname()
    port = 5000
    
    s = socket.socket()
    s.connect((host, port))
    print("Terhubung ke server.")

    # Step 1:
    # Generate generate_rsa_keys
    PUa, PRa = generate_rsa_keys()

    # Generate timestamp1
    timestamp = int(time.time())

    # Create request to PKA
    request = f"{PUa},{timestamp}"
    print(f"PUa: {PUa}")
    s.send(request.encode())

    # Step 2: 
    # Waiting to receive PUauth (signature), PUb, request, and timestamp1 
    while True:
        try:
            # Receive PUauth (signature)
            PUauth = s.recv(1024).decode()
            PUauth = tuple(map(int, PUauth.strip('()').split(',')))
            a, b = PUauth
            payload_response = s.recv(1024).decode()
            try:
                # Konversi string ke list integer menggunakan ast.literal_eval
                decoded_response_list = ast.literal_eval(payload_response) 
                decoded_response = decrypt_rsa((a,b), decoded_response_list)
            except Exception as e:
                print(f"Error decoding response: {e}")
                break
            print(f"decoded_response: {decoded_response}")
        except:
            print("Gagal menerima PUauth")
            break




    # print("Menerima my private key...")
    # my_private_key = s.recv(1024).decode()
    # my_private_key = tuple(map(int, my_private_key.strip('()').split(',')))
    # print("Private Key:", my_private_key)

    # print("Menerima peer public key...")
    # peer_public_key = s.recv(1024).decode()
    # peer_public_key = tuple(map(int, peer_public_key.strip('()').split(',')))
    # print("Public Key:", peer_public_key)

    # print("Menerima PKA public key...")
    # PKA_public_key = s.recv(1024).decode()
    # PKA_public_key = tuple(map(int, PKA_public_key.strip('()').split(',')))
    # print("PKA_Public Key:", PKA_public_key)

    # # initiate key exchange
    # # random string with length of 7 characters
    # DES_key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
    # print("original des key:", DES_key)

    # # signature pakai private key
    # signature_des_key = encrypt_rsa(my_private_key, DES_key)
    # str_signature_des_key = ','.join(map(str, signature_des_key))  

    # enkrip_DES_key = encrypt_rsa(peer_public_key, str_signature_des_key)
    # enkrip_DES_key = ','.join(map(str, enkrip_DES_key))  
    # s.send(enkrip_DES_key.encode())

    # key_bin = convert_key(DES_key)
    # keys = buat_keys(key_bin)

    # def terima():
    #     while True:
    #         try:
    #             data = s.recv(1024).decode()
    #             if not data:
    #                 break
    #             print("Pesan:", decrypt_ecb_mode(data, keys))
    #         except Exception as e:
    #             print("Error:", e)
    #             break
    
    # threading.Thread(target=terima).start()

    # while True:
    #     pesan = input("----------\n")
    #     if pesan == 'bye':
    #         s.send(pesan.encode())
    #         print("Keluar.")
    #         break
    #     else:
    #         bin_pesan = str_to_bin(pesan)
    #         enkrip_pesan = encrypt_ecb_mode(bin_pesan, keys)
    #         s.send(enkrip_pesan.encode())

    s.close()

if __name__ == "__main__":
    client_program()
