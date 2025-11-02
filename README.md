# PENGEMBANGAN-APLIKASI-KRIPTOGRAFI-SEDERHANA-MENGGUNAKAN-ALGORITMA-AES-256-CBC-MODE-

Aplikasi ini digunakan untuk:
- Enkripsi teks
- Dekripsi teks
- Enkripsi file (CSV/JSON atau file biasa)
- Dekripsi file

Prasyarat:
- Python 3.x
- Library:
    - cryptography
    - pandas

Tutorial Menggunakan Aplikasi:
1. Akan muncul menu dengan pilihan, yaitu:
   1. Encrypt Text
   2. Decrypt Text
   3. Encrypt File
   4. Decrypt File
   5. Exit

3. Pilih menu sesuai kebutuhan:
   - Encrypt Text → masukkan teks dan password
   - Decrypt Text → masukkan ciphertext Base64 dan password
   - Encrypt File → masukkan path file dan password
   - Decrypt File → masukkan path file .enc dan password
   - Exit → keluar dari program

Note:
- File yang dienkripsi maksimal 1 MB.
- Password tidak akan terlihat saat diketik.
