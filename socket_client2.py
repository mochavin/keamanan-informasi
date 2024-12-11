import socket
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import decrypt_rsa, generate_rsa_keys, encrypt_rsa
import time
import ast
from time import sleep
import random

def client_program():
    host = socket.gethostname()
    port = 5000
    
    s = socket.socket()
    s.connect((host, port))
    print("Terhubung ke server.")

    # Step 4:
    # Generate generate_rsa_keys
    PUb, PRb = generate_rsa_keys()
    Pua = None

    # Generate timestamp
    timestamp = int(time.time())

    # Create request to PKA
    request = f"{PUb},{timestamp}"
    print(f"PUb: {PUb}")
    s.send(request.encode())

    # Step 5: 
    # Waiting to receive PUauth (signature), PUa, request, and timestamp 
    while True:
        try:
            # Receive PUauth (signature)
            PUauth_received = s.recv(1024).decode()
            # change string to tuple
            PUauth = tuple(map(int, PUauth_received.strip('()').split(',')))
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
            # extract PUa from decoded_response
            try:
                # Get everything before the first second tuple
                first_tuple_str = decoded_response.split('),(')[0]
                # Clean up the string and convert to tuple
                PUa = tuple(map(int, first_tuple_str.strip('()').split(',')))
                break 
            except Exception as e:
                print(f"Error extracting PUb: {e}")
        except:
            print("Gagal menerima PUauth")
            break

    N2 = random.randint(1, 100)

    # Ready to Receive
    try:
        data = s.recv(1024).decode()
        print("\n---------- Receive Identitas A (IDA) and N1 encrypted with PUb ----------")
        # change string to list integer
        data = ast.literal_eval(data)
        data = decrypt_rsa(PRb, data)
        ida, N1 = data.rsplit(',', 1)
        print(f"IDA: {ida}")

        
        # Send N1 and N2 to A encrypted with PUa
        payload = f"{N1},{N2}"
        payload = encrypt_rsa(PUa, payload)
        # change list to string
        payload = ','.join(map(str, payload))
        print("N1", N1)
        print("N2", N2)
        s.send(payload.encode())

        print("\n---------- Receive N2 encrypted with PUb ----------")
        data = s.recv(1024).decode()
        data = ast.literal_eval(data)
        data = decrypt_rsa(PRb, data)
        N2recv = data
        print(f"N2recv: {N2recv}")
        if(str(N2) != N2recv):
            print("Error: N2 tidak sama")
            return
        else:
            print("Valid: N2 sama")

    except Exception as e:
        print("Error:", e)
    
    
    


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

    # # receive des key
    # DES_key = s.recv(1024).decode()
    # DES_key = list(map(int, DES_key.split(',')))
    # dekrip_DES_key = decrypt_rsa(my_private_key, DES_key)
    # dekrip_DES_key = list(map(int, dekrip_DES_key.split(',')))
    # rill_DES_key = decrypt_rsa(peer_public_key, dekrip_DES_key)
    # print("rill signature des key:", rill_DES_key)

    # key_bin = convert_key(rill_DES_key)
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
    #         bin_pesan = str_to_bin(pesan)
    #         # enkrip_pesan = encrypt_ecb_mode(bin_pesan, keys)
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
