Sistem Login dengan Keamanan RSA

Deskripsi

Sistem ini adalah sistem login yang menggunakan algoritma RSA untuk mengenkripsi password sebelum dikirim ke server. RSA adalah algoritma kriptografi asimetris yang menggunakan pasangan kunci publik dan privat untuk mengamankan data.

Fitur Utama

Enkripsi RSA pada Frontend: Password dienkripsi dengan RSA sebelum dikirim ke server.

Verifikasi pada Backend: Server mendekripsi password yang diterima dan mencocokkannya dengan database.

Registrasi Pengguna: Pengguna baru dapat mendaftar dengan password yang diamankan.

Login dan Logout: Sistem mendukung autentikasi dan sesi pengguna.

Dashboard: Halaman yang hanya bisa diakses setelah login.

Struktur File

index.php – Halaman utama (login form)

register.php – Halaman pendaftaran pengguna

dashboard.php – Halaman setelah login berhasil

logout.php – Untuk logout

includes/db.php – Konfigurasi koneksi database

includes/rsa.php – Implementasi RSA di backend

assets/js/rsa.js – Implementasi enkripsi RSA di frontend

login_system.sql – Skema database

Instalasi

Import Database

Buat database baru di MySQL.

Impor file login_system.sql ke dalam database.

Konfigurasi Database

Buka includes/db.php dan sesuaikan konfigurasi database.

Menjalankan Sistem

Pastikan server lokal seperti XAMPP atau LAMP berjalan.

Akses index.php melalui browser.

Cara Kerja RSA dalam Sistem Ini

Enkripsi Password di Frontend

Saat pengguna memasukkan password, RSA mengenkripsinya menggunakan kunci publik sebelum dikirim ke server.

Dekripsi di Backend

Server menggunakan kunci privat untuk mendekripsi password.

Password yang telah didekripsi dibandingkan dengan yang tersimpan di database.

Keamanan

Password tidak dikirim dalam bentuk teks biasa, tetapi telah dienkripsi menggunakan RSA.

Kunci privat hanya disimpan di server untuk menghindari akses dari klien.

Teknologi yang Digunakan

PHP – Backend dan logika server

MySQL – Basis data

JavaScript (JS) – Enkripsi RSA di frontend
