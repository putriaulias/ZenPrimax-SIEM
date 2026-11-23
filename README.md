# ZenPrimax SIEM Sederhana

SIEM laboratorium **PHP Native + MySQL** yang terpisah dari website
**ZenPrimax Premium Midtrans**. Tujuannya sederhana: membaca log aktivitas,
menandai pola tidak biasa, menampilkan bukti dan saran mitigasi, mengatur
Block/Unblock IP, dan mengunduh laporan PDF.

**Tidak ada Composer, npm, atau framework tambahan.** Kode memakai variabel
singkat seperti `$db`, `$ip`, `$row`, `$rule`, `$alert` dan JavaScript disimpan
terpisah pada `assets/app.js`.

## 1. Persiapan

- Windows, XAMPP PHP 8.2+ dengan PDO MySQL, MySQL/MariaDB.
- Website Premium Lab **sudah terpasang** dan mempunyai database
  `zenprimax_premium_lab` berisi `users`, `orders`, `audit_events`.
- Nama folder website Premium Lab diasumsikan
  `D:\xampp\htdocs\ZenPrimax-Premium-Midtrans`.
- Siapkan cadangan database dan folder website sebelum mengedit.

## 2. Instalasi SIEM

1. Ekstrak `ZenPrimax-SIEM-Sederhana` ke `D:\xampp\htdocs\`.
2. Pastikan Apache dan MySQL di XAMPP sudah hidup.
3. Buka `config.php` untuk memeriksa host, user, password, nama database,
   lokasi Apache access.log, dan alamat folder website Lab.
4. Buka terminal VS Code dan jalankan:

```powershell
cd D:\xampp\htdocs\ZenPrimax-SIEM-Sederhana
D:\xampp\php\php.exe install.php
```

5. **Simpan username dan password admin acak** yang muncul di terminal.
   Password ini tidak dicetak ulang saat installer dijalankan lagi.
6. SIEM tersedia di:

   http://localhost/ZenPrimax-SIEM-Sederhana/

Grafik **Activity Trend** pada Overview menyediakan preset 24 jam, 7 hari,
dan 30 hari, serta pilihan rentang tanggal kustom hingga 365 hari.

Installer menambahkan tabel `siem_blocks` **ke database Lab** tanpa menghapus
pesanan dan transaksi yang ada. Database SIEM terpisah bernama
`zenprimax_siem_simple`.

## 3. Menghubungkan tombol Block/Unblock ke website Premium Lab

**Langkah ini wajib agar IP yang diblokir benar-benar memperoleh HTTP 403.**

1. Salin `lab-patch/siem_bridge.php` ke folder utama website:

   `D:\xampp\htdocs\ZenPrimax-Premium-Midtrans\siem_bridge.php`

2. Buka file website `ZenPrimax-Premium-Midtrans/index.php`.
3. Temukan kode awal:

```php
require __DIR__ . '/app.php';
```

4. Tepat setelah baris itu, tambahkan:

```php
require __DIR__ . '/siem_bridge.php';
```

**Jangan memasang bridge ke `webhook.php`.** Midtrans harus tetap dapat
mengirim notifikasi pembayaran. Bridge memeriksa `REMOTE_ADDR`, bukan
`X-Forwarded-For` dari pengunjung. Pembatasan berlaku pada aplikasi PHP
website Lab, **bukan** firewall OS atau WAF jaringan.
Saat IP memiliki blokir aktif, setiap akses melalui middleware menampilkan
halaman HTTP 403 yang memuat alasan dan waktu berakhirnya blokir.

Jika user Anda mengakses website dari `127.0.0.1`, semua tab/browser pada
komputer yang sama akan memakai IP yang sama. Blokir IP localhost bisa
menolak seluruh tab website Premium, tetapi dashboard SIEM tetap bisa
membukanya kembali. Untuk uji multi-IP gunakan beberapa mesin dalam
jaringan lab atau proxy tepercaya yang dikonfigurasi dengan benar.

## 4. Memeriksa integrasi log

Masuk website Premium Lab, lalu:

- lakukan login **berhasil** dan login **gagal**;
- pilih produk dan lakukan checkout;
- simulasi pembayaran Midtrans Sandbox lalu tekan **Periksa Status**;
- ubah produk sebagai admin.

Dari SIEM, buka **Overview / Event Logs**. Halaman Event Logs menampilkan
seluruh log tersimpan dengan paginasi, filter tanggal mulai/akhir WIB, dan
pencarian. Collector akan membaca `audit_events` setiap dashboard dipoll
(10 detik). Untuk proses otomatis
**tanpa browser**, jadwalkan worker berikut:

```powershell
D:\xampp\php\php.exe D:\xampp\htdocs\ZenPrimax-SIEM-Sederhana\worker.php
```

Gunakan **Windows Task Scheduler** setiap 1 menit. Atur **Start in** ke
`D:\xampp\htdocs\ZenPrimax-SIEM-Sederhana`. Tidak perlu menjalankan
worker secara paralel berkali-kali; worker memiliki file lock.

**Istilah real-time:** ini *near-real-time polling* 10 detik ketika dashboard
terbuka dan hingga sekitar 1 menit jika Task Scheduler aktif. Bukan WebSocket
atau monitoring network packet real-time.

## 5. Aturan deteksi

| Rule | Ambang | Severity | Respons awal |
| --- | --- | --- | --- |
| Login gagal | 5 event / 3 menit / IP | High | Auto-block 24 jam |
| Lonjakan request HTTP | 30 / 1 menit / IP | High | Alert, blokir manual |
| Error HTTP 5xx | 3 / 5 menit / IP | Medium | Investigasi server |
| Checkout Pending >180 detik | 1 order | Medium | Investigasi, tanpa auto-block |
| Payment gagal | 3 / 10 menit / IP | Medium | Investigasi |
| Update produk | 1 event | Low | Audit admin |

Anda bisa membuat aturan baru pada halaman **Detection Rules** dengan nama,
jenis event, severity, threshold, rentang waktu, dan rekomendasi mitigasi.
Jenis event harus sama persis dengan event yang dicatat. Auto-block tersedia
sebagai pilihan dan nonaktif secara default. Aturan yang sudah ada juga dapat
diaktifkan/nonaktifkan dan opsi auto-block-nya diubah di halaman tersebut.
Auto-block hanya untuk event baru (selisih waktu maksimal 120 detik), bukan
log historis yang baru diimpor. Rule tidak dapat membuktikan serangan hanya
dari besarnya jumlah event; periksa bukti sebelum mitigasi.

**Catatan payment:** Pending selama >180 detik hanya *indikator* berdasarkan
asumsi baseline; Midtrans masih menentukan status final. Event timeout
dicatat sekali untuk setiap order. `orders.started_at` disimpan UTC dan
collector menghitung selisih waktu ketika order masih Pending.

## 6. Pengujian blokir

1. Masuk ke SIEM → `Blocked IPs`, isi IP sumber yang nyata terlihat di log.
2. Klik **Block IP (24 jam)**.
3. Akses kembali website Premium dari sumber tersebut. Hasil: HTTP 403.
4. Kembali ke SIEM → **Blocked IPs** → **Unblock IP**.
5. Akses website Premium kembali: boleh mengakses.

Status:
- `Active`: blokir berlaku selama maksimal 24 jam.
- `Expired`: masa berlaku lewat; akses dipulihkan secara otomatis.
- `Released`: hanya dihasilkan lewat klik Unblock oleh admin SIEM.

## 7. Detail audit dan laporan PDF

- Menu **Audit & Mitigasi** berisi severity, jenis event, IP, estimasi negara,
  identitas aktor, evidence JSON, rekomendasi dan tombol Block/Unblock.
- Tombol **PDF Temuan** membuat satu file laporan per alert.
- Tombol **Laporan PDF** pada header mengekspor ringkasan, semua alert
  terbaru, evidence, rekomendasi, dan riwayat blokir dengan layout A4 formal,
  ringkasan metrik, header/footer halaman, serta pemisahan bagian. Unduh
  langsung tanpa library PDF eksternal. Font PDF standar ditampilkan sebagai
  karakter latin.

## 8. Mengimpor CSV

Pada menu **Event Logs**, unggah file CSV ekspor audit aktivitas website
(kolom seperti `ID Log`, `Waktu (WIB)`, `Aksi`, dan `Alamat IP`) atau ekspor
**Vercel CDN Requests** (kolom seperti `timestampInMs`, `requestPath`,
`responseStatusCode`, dan `requestId`). Kedua format boleh dipilih bersamaan.

Maksimal 5 file, 10 MB per file, dan 10.000 event per unggahan. CSV audit
menggunakan waktu WIB; CSV Vercel menggunakan timestamp UTC. Pengunggahan
ulang event yang sama dilewati otomatis. Log historis tidak memicu auto-block.
Ekspor CDN Vercel yang tidak memuat alamat IP akan disimpan dengan IP
`unknown`; negara IP publik dari CSV audit tidak dicari ke layanan GeoIP.

## 9. Negara asal IP

Koneksi dari localhost `127.0.0.1`, jaringan privat, dan IP khusus untuk
simulasi **tidak punya negara publik yang dapat disimpulkan**; labelnya
`Lokal / Privat / Simulasi`.

Untuk perkiraan negara IP **publik**:

1. Buka `config.php` dan ubah `'geo_enabled' => true`.
2. PHP melakukan HTTPS lookup ke `https://ipwho.is/<IP>` dan menyimpan
   hasil pada `geo_cache`, supaya tidak meminta informasi untuk IP sama
   berkali-kali.
3. Internet dan ekstensi cURL diperlukan.

**Privasi:** jika diaktifkan, IP publik pengunjung dikirim kepada penyedia
layanan GeoIP pihak ketiga. Pelajari kebijakan data/kuota penyedia. Hasil
GeoIP hanya estimasi negara IP keluar/proxy, **bukan identitas negara orang
atau server penyerang yang pasti**. Lihat https://ipwhois.io/documentation.

## 10. Apache access log

Collector membaca `D:\xampp\apache\logs\access.log`, memfilter URL yang
mengandung `/ZenPrimax-Premium-Midtrans/` dan menghitung status HTTP.
Sesuaikan `apache_log` dan `lab_path` di `config.php` jika nama folder/port
berbeda. Bila access log tidak ada, fitur audit akun dan payment tetap jalan.

Metrik HTTP rate merupakan **indikasi request burst**, tidak membuktikan
DDoS terdistribusi. Perhatikan bahwa log Apache mencatat keseluruhan request
pada aplikasi sesuai konfigurasi Apache, bukan inspeksi paket jaringan.

## 11. Struktur file

```text
ZenPrimax-SIEM-Sederhana/
├── index.php               # Controller, routing, dan aksi SIEM
├── common.php              # Fungsi DB, detection rules, blokir
├── worker.php              # Collector audit, payment, Apache
├── csv_import.php          # Parser dan import CSV audit/Vercel
├── pages/
│   ├── login.php           # Halaman login
│   ├── overview.php        # Dashboard Overview
│   ├── audit.php           # Audit & Mitigasi
│   ├── logs.php            # Event Logs dan filter
│   ├── blocks.php          # Blocked IPs
│   └── rules.php           # Detection Rules
├── report.php              # Generator PDF sederhana
├── install.php             # Installer skema dan akun admin
├── config.php              # Koneksi dan lokasi sumber
├── assets/
│   ├── app.js              # Polling dan grafik real-time
│   └── style.css           # Antarmuka responsif
└── lab-patch/
    └── siem_bridge.php     # Middleware blokir untuk Lab
```

## 12. Batasan dan keamanan

- Prototype lokal untuk **capstone/laboratorium**; **jangan** langsung buka
  dashboard SIEM ke internet tanpa HTTPS, VPN dan penguatan autentikasi.
- Batasi izin akun database SIEM di staging. Contoh menggunakan root hanya
  untuk XAMPP lokal agar pemasangan mudah.
- Snapshot database sebaiknya dibuat sebelum uji login gagal, pengujian HTTP
  dan pengubahan aturan.
- Blokir berdasarkan IP bisa memengaruhi beberapa pengguna di NAT bersama.
  Jangan auto-block dari pembayaran lambat atau error HTTP 5xx saja.
- Tidak ada proses pembayaran atau kredensial Midtrans yang diubah.
- Website Lab yang terdahulu mempunyai Server Key/Signature Key yang sempat
  terlihat dalam screenshot. Rotasi key tersebut sebelum hosting.

## 13. Pemeriksaan awal

```powershell
cd D:\xampp\htdocs\ZenPrimax-SIEM-Sederhana
D:\xampp\php\php.exe -l index.php
D:\xampp\php\php.exe -l common.php
D:\xampp\php\php.exe -l worker.php
D:\xampp\php\php.exe -l csv_import.php
D:\xampp\php\php.exe worker.php
```

Jika worker menampilkan error koneksi MySQL, pastikan database website premium
sudah ada dan nama konfigurasinya sesuai. Jika login SIEM tidak bisa,
periksa password acak yang dicetak pada saat instalasi.
