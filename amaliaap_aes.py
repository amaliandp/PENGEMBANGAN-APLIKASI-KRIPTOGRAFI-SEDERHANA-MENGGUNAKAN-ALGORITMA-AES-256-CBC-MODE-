# Amalia Ananda Putri - 103052330078 - DS 47 01 - KEAMANAN DATA

# ============================================================
# Aplikasi AES-256 CBC Encryption & Decryption
# ============================================================
# Fitur:
# - Enkripsi teks
# - Dekripsi teks
# - Enkripsi file (termasuk CSV/JSON untuk data science)
# - Dekripsi file
# - Menggunakan AES-256 CBC + PBKDF2 untuk keamanan
# ============================================================

# Import library dasar
import os               # untuk manipulasi file & generate salt atau IV
import base64           # untuk encode/decode Base64
import getpass          # untuk input password tanpa terlihat
import pandas as pd     # membaca CSV/JSON (integrasi data science)

# Import library cryptography (AES, padding, PBKDF2)
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Batasi ukuran file yang boleh dienkripsi
MAX_FILE_SIZE = 1 * 1024 * 1024  # maks 1 MB

# ============================================================
# 1. Fungsi Derivasi Kunci (PBKDF2)
# ============================================================
def derive_key(password: str, salt: bytes) -> bytes:
    # Membuat objek PBKDF2 (untuk menghasilkan key dari password)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # SHA256 digunakan sebagai fungsi hash
        length=32,                  # Hasil key 32 byte (256-bit)
        salt=salt,                  # Salt acak agar password yang sama tapi key berbeda
        iterations=100000           # Iterasi banyak membuat brute-force lebih sulit
    )

    # return hasil derivasi key dalam bentuk bytes
    return kdf.derive(password.encode())

# ============================================================
# 2. Fungsi Load File (CSV/JSON akan diproses dulu oleh pandas)
# ============================================================
def load_file_for_encryption(file_path: str) -> str:
    # Memisahkan antara nama file dan ekstensi
    ext = os.path.splitext(file_path)[1].lower()

    # Jika CSV, maka baca dengan pandas lalu disimpan ulang
    if ext == ".csv":
        df = pd.read_csv(file_path)
        temp_path = "temp_to_encrypt.csv"
        df.to_csv(temp_path, index=False)  # disimpan ulang agar rapi
        return temp_path

    # Jika JSON, maka baca dengan pandas lalu disimpan ulang
    elif ext == ".json":
        df = pd.read_json(file_path)
        temp_path = "temp_to_encrypt.json"
        df.to_json(temp_path, orient="records", indent=4)
        return temp_path

    # Jika bukan CSV/JSON, maka file akan digunakan apa adanya
    else:
        return file_path

# ============================================================
# 3. Enkripsi Data Mentah (Bytes)
# ============================================================
def encrypt_bytes(data: bytes, password: str) -> bytes:
    # Generate salt acak (16 byte)
    salt = os.urandom(16)

    # Derive key AES dari password + salt
    key = derive_key(password, salt)

    # Generate IV acak (16 byte) untuk CBC
    iv = os.urandom(16)

    # Membuat padding agar panjang datanya kelipatan 16 byte
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    # Buat objek AES-CBC untuk enkripsi
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Hasil ciphertext setelah enkripsi
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Gabungkan salt + IV + ciphertext dalam satu paket
    return salt + iv + ciphertext

# ============================================================
# 4. Dekripsi Data Mentah (Bytes)
# ============================================================
def decrypt_bytes(blob: bytes, password: str) -> bytes:
    # Ambil salt dari 16 byte pertama
    salt = blob[:16]

    # Ambil IV dari byte ke 17–32
    iv = blob[16:32]

    # Sisanya adalah ciphertext
    ciphertext = blob[32:]

    # Derive kembali key menggunakan password + salt
    key = derive_key(password, salt)

    # Buat objek AES-CBC untuk dekripsi
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Dekripsi ciphertext
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Hapus padding agar plaintext kembali normal
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()

    # Kembalikan hasil plaintext
    return plain

# ============================================================
# 5. Enkripsi Teks (Input Manual)
# ============================================================
def encrypt_text():
    # Ambil plaintext dari user
    plaintext = input("Masukkan plaintext: ")

    # Password dimasukkan secara tersembunyi
    password = getpass.getpass("Password: ")

    # Enkripsi data plaintext menjadi bytes
    blob = encrypt_bytes(plaintext.encode(), password)

    # Encode ke Base64 agar mudah disalin
    encoded = base64.b64encode(blob).decode()

    # Tampilkan hasil ciphertext
    print("\n=== Ciphertext (Base64) ===")
    print(encoded)
    print("===========================\n")

# ============================================================
# 6. Dekripsi Teks (Input Manual)
# ============================================================
def decrypt_text():
    # Ambil ciphertext dalam format Base64
    ciphertext = input("Masukkan ciphertext Base64: ")

    # Ambil password untuk dekripsi
    password = getpass.getpass("Password: ")

    try:
        # Decode Base64 kembali menjadi bytes
        blob = base64.b64decode(ciphertext)

        # Dekripsi data
        plain = decrypt_bytes(blob, password)

        # Tampilkan plaintext hasil dekripsi
        print("\n=== Hasil Dekripsi ===")
        print(plain.decode())
        print("======================\n")

    except Exception as e:
        # Jika password salah atau ciphertext rusak
        print("Gagal mendekripsi! Error:", e)


# ============================================================
# 7. Enkripsi File
# ============================================================
def encrypt_file():
    # Path file dari user
    file_path = input("Masukkan path file: ")

    # Cek apakah file ada
    if not os.path.exists(file_path):
        print("File tidak ditemukan!")
        return

    # Cek ukuran file apakah melebihi batas
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        print("Ukuran file melebihi 1 MB.")
        return

    # Jika CSV/JSON, maka diproses dulu oleh pandas
    actual_path = load_file_for_encryption(file_path)

    # Baca file sebagai bytes
    with open(actual_path, "rb") as f:
        data = f.read()

    # Password untuk enkripsi
    password = getpass.getpass("Password: ")

    # Enkripsi bytes file
    blob = encrypt_bytes(data, password)

    # Encode ke Base64 agar aman disimpan sebagai teks
    encoded = base64.b64encode(blob).decode()

    # Hasil disimpan dalam file .enc
    output_path = file_path + ".enc"

    # Tulis hasil ciphertext ke file
    with open(output_path, "w") as f:
        f.write(encoded)

    # Beri informasi hasil
    print(f"\nFile terenkripsi disimpan sebagai: {output_path}\n")


# ============================================================
# 8. Dekripsi File
# ============================================================
def decrypt_file():
    # Input file .enc
    file_path = input("Masukkan path file .enc: ")

    # Cek apakah file ada
    if not os.path.exists(file_path):
        print("File tidak ditemukan!")
        return

    # Input password untuk dekripsi
    password = getpass.getpass("Password: ")

    try:
        # Baca file terenkripsi
        encoded = open(file_path).read()

        # Decode Base64 menjadi bytes
        blob = base64.b64decode(encoded)

        # Dekripsi isinya
        plain = decrypt_bytes(blob, password)

        # Hasil dikembalikan ke nama asli (hapus .enc)
        original_path = file_path.replace(".enc", "")

        # Simpan file hasil dekripsi
        with open(original_path, "wb") as f:
            f.write(plain)

        print(f"\nFile hasil dekripsi disimpan sebagai: {original_path}\n")

    except Exception as e:
        # Muncul jika password salah atau file rusak
        print("Gagal mendekripsi!", e)


# ============================================================
# 9. Menu Utama Aplikasi
# ============================================================
def main():
    # Loop agar program terus berjalan sampai user memilih Exit
    while True:
        print("""
===============================
   AES-256 CBC Encryption App
===============================
1. Encrypt Text
2. Decrypt Text
3. Encrypt File
4. Decrypt File
5. Exit
        """)

        # Ambil pilihan menu dari user
        choice = input("Pilih menu: ")

        # Menjalankan fungsi berdasarkan pilihan dari user
        if choice == "1":
            encrypt_text()
        elif choice == "2":
            decrypt_text()
        elif choice == "3":
            encrypt_file()
        elif choice == "4":
            decrypt_file()
        elif choice == "5":
            print("Keluar...")
            break  # keluar dari loop
        else:
            print("Pilihan tidak valid. Coba lagi.")


# Program dijalankan mulai dari sini
if __name__ == "__main__":
    main()
