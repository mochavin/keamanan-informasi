import socket
import ast
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import encrypt_rsa, generate_rsa_keys, decrypt_rsa
import random
import time
from time import sleep

def send_new_DES_key(s, PUb, PRa):
    while True:
        sleep(7200)  # 2 hours in seconds
        DES_key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
        print("Generated new DES key:", DES_key)
        
        # Encrypt and sign the DES key
        signature_des_key = encrypt_rsa(PRa, DES_key)
        signature_des_key = ','.join(map(str, signature_des_key))  
        encrypted_DES_key = encrypt_rsa(PUb, signature_des_key)
        encrypted_DES_key = ','.join(map(str, encrypted_DES_key))
        
        # Send the new DES key
        s.send(f"DES_KEY:{encrypted_DES_key}".encode())
        print("\n---------- Send new DES key to Client B ----------")
        print("New DES key sent to Client B.")
        print("---------------------------------------------------\n")

        # Update the keys variable with the new DES key
        key_bin = convert_key(DES_key)
        global keys
        keys = buat_keys(key_bin)



def client_program():
    host = socket.gethostname()
    port = 5000
    
    s = socket.socket()
    s.connect((host, port))
    print("Terhubung ke server.")

    # Step 1:
    # Generate generate_rsa_keys
    PUa, PRa = generate_rsa_keys()
    PUb = None

    # Generate timestamp1
    timestamp = int(time.time())

    # Create request to PKA
    request = f"{PUa},{timestamp}"
    print(f"PUa: {PUa}")
    s.send(request.encode())

    # Step 2: 
    # Waiting to receive PUauth (signature), PUb, request, and timestamp1 
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
        print(f"decoded_response: {decoded_response}")
        # Extract PUb from decoded_response
        try:
            # Get everything before the first second tuple
            first_tuple_str = decoded_response.split('),(')[0]
            # Clean up the string and convert to tuple
            PUb = tuple(map(int, first_tuple_str.strip('()').split(',')))
        except Exception as e:
            print(f"Error extracting PUb: {e}")
    except:
        print("Gagal menerima PUauth")

    N1 = random.randint(1, 100)
    DES_key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))

    
    # Ready to Receive
    try:
        # Step 3:
        # Send Identitas A (IDA) and N1 encrypted with PUb
        print("\n---------- Send Identitas A (IDA) and N1 encrypted with PUb ----------")
        payload = f"IDA,{N1}"
        # encrypt payload with PUb
        payload = encrypt_rsa(PUb, payload)
        # change list to string
        payload = ','.join(map(str, payload))
        print(f"payload: {payload}")
        s.send(payload.encode())
        print("\n---------- Receive N1 and N2 encrypted with PUa ----------")
        data = s.recv(1024).decode()
        data = ast.literal_eval(data)
        data = decrypt_rsa(PRa, data)
        N1recv, N2recv = data.split(',', 1)
        print("N1", N1)
        print(f"N1recv: {N1recv}")
        print(f"N2: {N2recv}")
        if(str(N1) != N1recv):
            print("Error: N1 tidak sama")
            return
        else:
            print("Valid: N1 sama")
        
        # Send N2 encrypted with PUb
        payload = f"{N2recv}"
        payload = encrypt_rsa(PUb, payload)
        # change list to string
        payload = ','.join(map(str, payload))
        s.send(payload.encode())

        # Cryptosystems to send DES key
        print("original des key:", DES_key)

        # signature pakai private key
        signature_des_key = encrypt_rsa(PRa, DES_key)
        # change list to string
        signature_des_key = ','.join(map(str, signature_des_key))  

        # encrypt signature des key
        encrypted_DES_key = encrypt_rsa(PUb, signature_des_key)
        # change list to string
        encrypted_DES_key = ','.join(map(str, encrypted_DES_key))
        s.send(encrypted_DES_key.encode())

    except Exception as e:
        print("Error:", e)

    # Send "bye" to server to disconnect
    s.send(b'bye')

    # Start thread to send new DES key every 2 hours
    

    key_bin = convert_key(DES_key)
    global keys
    keys = buat_keys(key_bin)

    # Start connect to Client B
    try:
        direct_host = socket.gethostname()  
        direct_port = 6000  # Define a port for direct connection

        direct_sock = socket.socket()
        direct_sock.connect((direct_host, direct_port))
        print("Terhubung langsung ke Client B.")
        
        threading.Thread(target=send_new_DES_key, args=(direct_sock, PUb, PRa), daemon=True).start()
        

        def terima_direct():
            while True:
                try:
                    data = direct_sock.recv(1024).decode()
                    if not data:
                        break
                    print("Pesan dari Client B:", decrypt_ecb_mode(data, keys))
                except Exception as e:
                    print("Error:", e)
                    break

        threading.Thread(target=terima_direct).start()

        while True:
            pesan = input("----------\n")
            if pesan == 'bye':
                direct_sock.send(pesan.encode())
                print("Keluar dari koneksi langsung.")
                break
            else:
                bin_pesan = str_to_bin(pesan)
                enkrip_pesan = encrypt_ecb_mode(bin_pesan, keys)
                direct_sock.send(enkrip_pesan.encode())

        direct_sock.close()

    except Exception as e:
        print("Gagal terhubung langsung ke Client B:", e)

    s.close()

if __name__ == "__main__":
    client_program()
