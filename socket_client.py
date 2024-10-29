# https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client
# socket client

import socket
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode

def client_program():
    # Initialize DES encryption
    KEY = "secretky"  # Shared secret key (8 chars)
    key_bin = convert_key(KEY)
    keys = buat_keys(key_bin)
    
    # Set up socket client
    host = socket.gethostname()
    port = 5000
    
    client_socket = socket.socket()
    
    try:
        client_socket.connect((host, port))
        print("Terhubung ke server. Mulai percakapan!")
        
        while True:
            # Get message from user
            message = input("Pesan Anda: ")
            if message.lower() == 'quit':
                break
            
            # Encrypt and send message
            bin_message = str_to_bin(message)
            encrypted_hex = encrypt_ecb_mode(bin_message, keys)
            client_socket.send(encrypted_hex.encode())

            # Wait for response
            print("Menunggu pesan dari server...")
            
            # Receive and decrypt response
            encrypted_response = client_socket.recv(1024).decode()
            if not encrypted_response:
                break

            # Receive encrypted message
            print("Cipher (Hex - ECB):", encrypted_response)
                
            decrypted_response = decrypt_ecb_mode(encrypted_response, keys)
            print("------------------")
            print(f"Pesan terdekripsi: {decrypted_response}")


    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    client_program()
