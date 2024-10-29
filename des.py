"""
Implementasi DES Algorithm

Nama  : Moch. Avin
NRP   : 5025221061
Kelas : Keamanan Informasi (B)


Keterbatasan: maksimal 8 karakter saja
Note: 
- jika key lebih dari 8 karakter, akan dipotong ke 8 karakter
- jika key kurang dari 8 karakter, akan diisi dengan '0'
- implementasi ini terinspirasi dari https://medium.com/@ziaullahrajpoot/data-encryption-standard-des-dc8610aafdb3
- testing dilakukan menggunakan http://des.online-domain-tools.com/

"""

# Tabel Permutasi Awal
tbl_ip = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Tabel Permutasi PC1
tbl_pc1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

# Banyak geser kiri per ronde
shift_left = [1, 1, 2, 2,
             2, 2, 2, 2,
             1, 2, 2, 2,
             2, 2, 2, 1]

# Tabel Permutasi PC2
tbl_pc2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Tabel Ekspansi E-box
tbl_e = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Tabel S-box
s_box = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Tabel P-box
tbl_p = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Tabel Permutasi Invers IP
tbl_ip_inv = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

def str_to_bin(inp):
    bin_str = ''
    for c in inp:
        bin_c = format(ord(c), '08b')
        bin_str += bin_c
    # Tambahkan padding agar panjangnya kelipatan 64 bit
    padding_len = (64 - len(bin_str) % 64) if len(bin_str) % 64 != 0 else 0
    bin_str = bin_str.ljust(len(bin_str) + padding_len, '0')
    return bin_str

def bin_to_ascii(bin_s):
    ascii_s = ''.join([chr(int(bin_s[i:i+8], 2)) for i in range(0, len(bin_s), 8)])
    return ascii_s

def bin_to_hex(bin_s):
    hex_s = hex(int(bin_s, 2))[2:].upper()
    # Pastikan kelipatan 16 digit hexa (64 bit per blok)
    hex_length = (len(bin_s) // 4)
    hex_s = hex_s.zfill(hex_length)
    return hex_s

def hex_to_bin(hex_s):
    # Konversi hex ke binary, pastikan panjangnya benar
    bin_s = bin(int(hex_s, 16))[2:].zfill(len(hex_s) * 4)
    return bin_s

def permute_ip(bin_inp):
    # Lakukan permutasi awal
    res = ['0'] * 64
    for i in range(64):
        res[i] = bin_inp[tbl_ip[i] - 1]
    return ''.join(res)

def convert_key(key_input):
    if len(key_input) < 8:
        print("Key kurang dari 8 karakter, akan diisi dengan '0'")
        key_input = key_input.ljust(8, '0')
    elif len(key_input) > 8:
        print("Key lebih dari 8 karakter, akan dipotong ke 8 karakter.")
        key_input = key_input[:8]
    print("Key Asli:", key_input)
    bin_key = ''
    for k in key_input:
        bin_k = format(ord(k), '08b')
        bin_key += bin_k
    return bin_key

def buat_keys(key_bin):
    # Bikin round keys
    pc1 = ''.join([key_bin[b - 1] for b in tbl_pc1])
    c = pc1[:28]
    d = pc1[28:]
    keys = []
    for r in range(16):
        c = c[shift_left[r]:] + c[:shift_left[r]]
        d = d[shift_left[r]:] + d[:shift_left[r]]
        cd = c + d
        round_key = ''.join([cd[b - 1] for b in tbl_pc2])
        keys.append(round_key)
    return keys

def xor_bin(bin1, bin2):
    return ''.join(['0' if bin1[i] == bin2[i] else '1' for i in range(len(bin1))])

def encrypt_ecb(block, keys):
    ip = permute_ip(block)
    left = ip[:32]
    right = ip[32:]
    for r in range(16):
        # Ekspansi
        exp = ''.join([right[i - 1] for i in tbl_e])
        # XOR dengan key
        xor = ''.join([str(int(exp[i]) ^ int(keys[r][i])) for i in range(48)])
        # Bagi jadi 8 grup 6-bit
        grp = [xor[i:i+6] for i in range(0, 48, 6)]
        # S-box
        sb = ''
        for i in range(8):
            row = int(grp[i][0] + grp[i][-1], 2)
            col = int(grp[i][1:-1], 2)
            val = s_box[i][row][col]
            sb += format(val, '04b')
        # P-box
        p = ''.join([sb[tbl_p[i] - 1] for i in range(32)])
        # XOR dengan left
        new_right = ''.join([str(int(left[j]) ^ int(p[j])) for j in range(32)])
        left, right = right, new_right
    # Gabung lagi
    final = right + left
    # Permutasi akhir
    cipher_bin = ''.join([final[tbl_ip_inv[i] - 1] for i in range(64)])
    return cipher_bin

def decrypt_ecb(block, keys):
    # Ubah binary blok
    ip = permute_ip(block)
    left = ip[:32]
    right = ip[32:]
    for r in range(16):
        # Ekspansi
        exp = ''.join([right[i - 1] for i in tbl_e])
        # XOR dengan key (kunci dibalik urutannya)
        key_used = keys[15 - r]
        xor = ''.join([str(int(exp[i]) ^ int(key_used[i])) for i in range(48)])
        # Bagi jadi 8 grup 6-bit
        grp = [xor[i:i+6] for i in range(0, 48, 6)]
        # S-box
        sb = ''
        for i in range(8):
            row = int(grp[i][0] + grp[i][-1], 2)
            col = int(grp[i][1:-1], 2)
            val = s_box[i][row][col]
            sb += format(val, '04b')
        # P-box
        p = ''.join([sb[tbl_p[i] - 1] for i in range(32)])
        # XOR dengan left
        new_right = ''.join([str(int(left[j]) ^ int(p[j])) for j in range(32)])
        left, right = right, new_right
    # Gabung lagi
    final = right + left
    # Permutasi akhir
    plain_bin = ''.join([final[tbl_ip_inv[i] - 1] for i in range(64)])
    return plain_bin

def encrypt_cbc(bin_inp, keys, iv_bin):
    blocks = [bin_inp[i:i+64] for i in range(0, len(bin_inp), 64)]
    cipher_blocks = []
    previous = iv_bin
    for block in blocks:
        # Pastikan blok berukuran 64 bit
        if len(block) < 64:
            block = block.ljust(64, '0')
        # XOR dengan previous ciphertext (IV untuk blok pertama)
        block = xor_bin(block, previous)
        # Enkripsi blok
        cipher = encrypt_ecb(block, keys)
        cipher_blocks.append(cipher)
        previous = cipher
    cipher_bin = ''.join(cipher_blocks)
    cipher_hex = bin_to_hex(cipher_bin)
    print("Cipher (Hex - CBC):", cipher_hex)
    return cipher_hex

def decrypt_cbc(cipher_hx, keys, iv_bin):
    # Ubah hex jadi binary
    cipher_bin = bin(int(cipher_hx, 16))[2:].zfill(64 * ((len(cipher_hx) + 15) // 16))
    blocks = [cipher_bin[i:i+64] for i in range(0, len(cipher_bin), 64)]
    plain_blocks = []
    previous = iv_bin
    for block in blocks:
        # Dekripsi blok
        decrypted = decrypt_ecb(block, keys)
        # XOR dengan previous ciphertext (IV untuk blok pertama)
        plain = xor_bin(decrypted, previous)
        plain_blocks.append(plain)
        previous = block
    plain_bin = ''.join(plain_blocks)
    # Menghapus padding '0's yang ditambahkan selama enkripsi
    plain_bin = plain_bin.rstrip('0')
    plain_ascii = bin_to_ascii(plain_bin)
    # print("Hasil Dekripsi Cipher (ASCII - CBC):", plain_ascii)
    return plain_ascii

def encrypt_ecb_mode(bin_inp, keys):
    blocks = [bin_inp[i:i+64] for i in range(0, len(bin_inp), 64)]
    cipher_blocks = []
    
    for block in blocks:
        # Pastikan blok berukuran 64 bit
        if len(block) < 64:
            block = block.ljust(64, '0')
        cipher_block = encrypt_ecb(block, keys)
        cipher_blocks.append(cipher_block)
    
    cipher_bin = ''.join(cipher_blocks)
    cipher_hex = bin_to_hex(cipher_bin)
    print("Cipher (Hex - ECB):", cipher_hex)
    return cipher_hex

def decrypt_ecb_mode(cipher_hx, keys):
    cipher_bin = hex_to_bin(cipher_hx)
    blocks = [cipher_bin[i:i+64] for i in range(0, len(cipher_bin), 64)]
    plain_blocks = []
    
    for block in blocks:
        decrypted_block = decrypt_ecb(block, keys)
        plain_blocks.append(decrypted_block)
    
    plain_bin = ''.join(plain_blocks)
    
    # Hapus padding dengan mencari karakter yang berarti
    # Konversi setiap 8 bit ke karakter sampai menemui padding
    plain_chars = []
    for i in range(0, len(plain_bin), 8):
        char_bin = plain_bin[i:i+8]
        if len(char_bin) == 8:  # Pastikan panjang 8 bit
            char_val = int(char_bin, 2)
            if char_val != 0:  # Bukan padding
                plain_chars.append(chr(char_val))
    
    plain_text = ''.join(plain_chars)
    # print("Hasil Dekripsi Cipher (ASCII - ECB):", plain_text)
    return plain_text


# Fungsi utama untuk enkripsi dan dekripsi dengan pilihan mode
# def main():
    user = input("Masukkan string: ")
    
    key_input = input("Masukkan key (8 karakter): ")
    
    # Pastikan key tepat 8 karakter
    if len(key_input) < 8:
        print("Key kurang dari 8 karakter, akan diisi dengan '0'.")
        key_input = key_input.ljust(8, '0')
    elif len(key_input) > 8:
        print("Key lebih dari 8 karakter, akan dipotong ke 8 karakter.")
        key_input = key_input[:8]
    
    key_bin = convert_key(key_input)
    
    keys = buat_keys(key_bin)
    
    # Pilih mode
    mode = input("Pilih mode (ECB/CBC): ").strip().upper()
    while mode not in ['ECB', 'CBC']:
        print("Mode tidak valid. Pilih antara ECB atau CBC.")
        mode = input("Pilih mode (ECB/CBC): ").strip().upper()
    
    if mode == 'ECB':
        bin_inp = str_to_bin(user)
        print("========== Hasil ==========")
        ciph = encrypt_ecb_mode(bin_inp, keys)
        decr = decrypt_ecb_mode(ciph, keys)
    else:
        # Input IV
        iv = input("Masukkan IV (8 karakter): ")
        if len(iv) < 8:
            print("IV kurang dari 8 karakter, akan diisi dengan '0'.")
            iv = iv.ljust(8, '0')
        elif len(iv) > 8:
            print("IV lebih dari 8 karakter, akan dipotong ke 8 karakter.")
            iv = iv[:8]
        iv_bin = convert_key(iv)
        
        print("========== Hasil ==========")
        bin_inp = str_to_bin(user)
        ciph = encrypt_cbc(bin_inp, keys, iv_bin)
        decr = decrypt_cbc(ciph, keys, iv_bin)

# if __name__ == "__main__":
#     main()
