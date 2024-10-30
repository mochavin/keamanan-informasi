import socket
import threading

# Array untuk koneksi
clnts = []

def hndle(conn, addr):
    print(f"Tersambung dengan: {addr}")
    while True:
        try:
            # Terima pesan terenkripsi
            enc_hex = conn.recv(1024).decode()
            if not enc_hex:
                break
            print(f"Cipher (Hex - ECB) dari {addr}: {enc_hex}")
            
            # Jika pesan adalah "bye", klien keluar
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
    
    # Hapus koneksi
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
    host = socket.gethostname()
    port = 5000
    
    srv_sock = socket.socket()
    srv_sock.bind((host, port))
    srv_sock.listen(5)
    print("Server siap, tunggu klien...")

    # Jalankan listener
    threading.Thread(target=inp_listen, args=(srv_sock,)).start()

    while True:
        try:
            # Terima koneksi
            conn, addr = srv_sock.accept()
            clnts.append(conn)
            
            # Mulai thread untuk tiap klien
            threading.Thread(target=hndle, args=(conn, addr)).start()
        except:
            break

if __name__ == "__main__":
    srv()
