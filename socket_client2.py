import socket
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import decrypt_rsa

def client_program():
    host = socket.gethostname()
    port = 5000
    
    s = socket.socket()
    s.connect((host, port))
    print("Terhubung ke server.")

    print("Menerima my private key...")
    my_private_key = s.recv(1024).decode()
    my_private_key = tuple(map(int, my_private_key.strip('()').split(',')))
    print("Private Key:", my_private_key)

    print("Menerima peer public key...")
    peer_public_key = s.recv(1024).decode()
    peer_public_key = tuple(map(int, peer_public_key.strip('()').split(',')))
    print("Public Key:", peer_public_key)

    print("Menerima PKA public key...")
    PKA_public_key = s.recv(1024).decode()
    PKA_public_key = tuple(map(int, PKA_public_key.strip('()').split(',')))
    print("PKA_Public Key:", PKA_public_key)

    # receive des key
    DES_key = s.recv(1024).decode()
    DES_key = list(map(int, DES_key.split(',')))
    dekrip_DES_key = decrypt_rsa(my_private_key, DES_key)
    dekrip_DES_key = list(map(int, dekrip_DES_key.split(',')))
    rill_DES_key = decrypt_rsa(peer_public_key, dekrip_DES_key)
    print("rill signature des key:", rill_DES_key)

    key_bin = convert_key(rill_DES_key)
    keys = buat_keys(key_bin)

    def terima():
        while True:
            try:
                data = s.recv(1024).decode()
                if not data:
                    break
                print("Pesan:", decrypt_ecb_mode(data, keys))
            except Exception as e:
                print("Error:", e)
                break
    
    threading.Thread(target=terima).start()

    while True:
        pesan = input("----------\n")
        if pesan == 'bye':
            bin_pesan = str_to_bin(pesan)
            # enkrip_pesan = encrypt_ecb_mode(bin_pesan, keys)
            s.send(pesan.encode())
            print("Keluar.")
            break
        else:
            bin_pesan = str_to_bin(pesan)
            enkrip_pesan = encrypt_ecb_mode(bin_pesan, keys)
            s.send(enkrip_pesan.encode())

    s.close()

if __name__ == "__main__":
    client_program()
