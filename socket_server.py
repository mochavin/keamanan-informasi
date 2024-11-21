import socket
import threading
from rsa import generate_rsa_keys
import time

# Array untuk koneksi
clnts = []
PUauth = None  # Store public key globally

def send_public_key():
    # Convert public key to string and send to all clients
    key_str = str(PUauth)
    PUa, PRa = generate_rsa_keys()
    PUb, PRb = generate_rsa_keys()

    clnts[0].send(str(PRa).encode())
    clnts[1].send(str(PRb).encode())
    clnts[0].send(str(PUb).encode())
    clnts[1].send(str(PUa).encode())
    time.sleep(1)
    
    for c in clnts:
        try:
            c.send(key_str.encode())
        except:
            print(f"Gagal mengirim kunci ke client")

def hndle(conn, addr):
    print(f"Tersambung dengan: {addr}")

    while True:
        try:
            # Terima pesan terenkripsi
            enc_hex = conn.recv(1024).decode()
            if not enc_hex:
                break
            print(f"Cipher (Hex - ECB) dari {addr}: {enc_hex}")
            
            if enc_hex.lower() == "bye":
                print(f"{addr} keluar.")
                break

            # Kirim ke klien lain
            for c in clnts:
                if c != conn:
                    c.send(enc_hex.encode())
                    
        except:
            print(f"Kesalahan dengan {addr}")
            break
    
    clnts.remove(conn)
    conn.close()

def inp_listen(srv_sock):
    while True:
        cmd = input("Ketik 'quit' untuk hentikan server: ")
        if cmd.lower() == "quit":
            print("Matikan server dan putus koneksi")
            for c in clnts:
                c.close()
            srv_sock.close()
            break

def srv():
    global PUauth
    PUauth, PRauth = generate_rsa_keys()
    host = socket.gethostname()
    port = 5000
    
    srv_sock = socket.socket()
    srv_sock.bind((host, port))
    srv_sock.listen(5)
    print("Server siap, tunggu klien...")

    threading.Thread(target=inp_listen, args=(srv_sock,)).start()

    while True:
        try:
            conn, addr = srv_sock.accept()
            clnts.append(conn)
            
            # Kirim PUauth ketika ada 2 client
            if len(clnts) == 2:
                print("2 client terkoneksi, mengirim public key...")
                send_public_key()
            
            threading.Thread(target=hndle, args=(conn, addr)).start()
        except:
            break

if __name__ == "__main__":
    srv()