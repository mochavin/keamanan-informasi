import socket
import threading
from rsa import generate_rsa_keys, encrypt_rsa
import time
from time import sleep

# Array untuk koneksi
clnts = []
timestamp1, timestamp2 = None, None
req1, req2 = None, None

PUa, PUb = None, None
PUauth, PRauth = None, None

def send_public_key():
    print("2 client terkoneksi, mengirim public key...")
    # Step 2:
    # Send PUb, req1, and timestamp1 to client A. 
    # Send PUauth to client A
    clnts[0].send(str(PUauth).encode())
    print("Sent PUauth to client A")
    # Give Signed message
    message_A = f"{PUb},{req1},{timestamp1}"
    signed_message_A = encrypt_rsa(PRauth, message_A)
    clnts[0].send(str(signed_message_A).encode())
    print("Sent signed message to client A")

    # Step 5:
    # Send PUa, req2, and timestamp2 to client B.
    # Send PUauth to client B
    clnts[1].send(str(PUauth).encode())
    print("Sent PUauth to client B")
    # Give Signed message
    message_B = f"{PUa},{req2},{timestamp2}"
    signed_message_B = encrypt_rsa(PRauth, message_B)
    clnts[1].send(str(signed_message_B).encode())
    print("Sent signed message to client B")
    



def hndle(conn, addr):
    global timestamp1, timestamp2, PUa, PUb, req1, req2
    print(f"Tersambung dengan: {addr}")

    # Receive public key from client
    if(len(clnts) == 1):
        message_A = conn.recv(1024).decode()
        req1 = message_A
        PUa, timestamp1 = message_A.rsplit(',', 1)
        print(f"Timestamp A: {timestamp1}")
        print(f"Public key A: {PUa}")
    elif (len(clnts) == 2):
        message_B = conn.recv(1024).decode()
        req2 = message_B
        PUb, timestamp2 = message_B.rsplit(',', 1)
        print(f"Timestamp B: {timestamp2}")
        print(f"Public key B: {PUb}")


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
    global PUauth, PRauth
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

            threading.Thread(target=hndle, args=(conn, addr)).start()

            # Waiting for timestamp
            sleep(1)
            
            # Kirim PUauth ketika ada 2 client
            if len(clnts) == 2 and timestamp1 and timestamp2:
                send_public_key()
            
        except:
            break

if __name__ == "__main__":
    srv()