# https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client
# socket server

import socket
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode

def server_program():
    # Initialize DES encryption
    KEY = "secretky"  # Shared secret key (8 chars)
    key_bin = convert_key(KEY)
    keys = buat_keys(key_bin)
    
    # Set up socket server
    host = socket.gethostname()
    port = 5000
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    
    print("Server dimulai. Menunggu klien...")
    conn, address = server_socket.accept()
    print(f"Terhubung dengan: {address}")
    try:
        while True:
            # Receive encrypted message
            encrypted_hex = conn.recv(1024).decode()
            if not encrypted_hex:
                break

            # Receive encrypted message
            print("Cipher (Hex - ECB):", encrypted_hex)
            
            # Decrypt received message
            decrypted_msg = decrypt_ecb_mode(encrypted_hex, keys)
            print(f"Pesan terdekripsi: {decrypted_msg}")
            
            # Get response from server user
            response = input("Pesan Anda: ")
            if response.lower() == 'quit':
                break
                
            # Encrypt and send response
            bin_response = str_to_bin(response)
            encrypted_response = encrypt_ecb_mode(bin_response, keys)
            print("------------------")
            conn.send(encrypted_response.encode())
            
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    server_program()