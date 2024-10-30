import socket
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode

KEY = "secretky"  
key_bin = convert_key(KEY)
keys = buat_keys(key_bin)

def client_program():
    host = socket.gethostname()
    port = 5000
    
    s = socket.socket()
    s.connect((host, port))
    print("Terhubung ke server.")

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
