# Skenario Serangan (untuk dicek dan dipoles oleh adik)

Ini cerita serangan palsu yang dipakai untuk demo. Tugasmu:
1. Baca ceritanya sampai paham.
2. Cek apakah masuk akal (kalau ada yang janggal, catat dan tanya).
3. Tulis ulang versi singkatnya dengan bahasamu sendiri (maks 1 halaman).
4. Cari di attack.mitre.org nama teknik untuk setiap langkah dan cocokkan dengan file
   `backend/data/mitre_map.csv`.

## Tokoh dan perangkat
- **WS-ENG-07** (10.10.5.23): komputer staf teknisi. Sudah terinfeksi lewat email phishing.
- **WS-ADM-03** (10.10.5.12): komputer admin milik Pak Budi (akun `budi.s`).
- **SCADA-ENG-01** (10.10.9.20): komputer teknik yang terhubung ke jaringan industri (OT).
- **GEN-CTRL-01** (10.10.9.50): pengendali genset (PLC) yang bicara lewat protokol Modbus.
- **SCADA-HMI-01** (10.10.9.5): layar operator resmi genset. Hanya ini yang seharusnya memberi perintah.

## Alur serangan
| Jam   | Kejadian | Teknik MITRE |
|-------|----------|--------------|
| 20:42 | Staf membuka email phishing. WS-ENG-07 mulai berhubungan dengan server asing (203.0.113.45). | T1566 Phishing |
| 21:00 | Dari WS-ENG-07, penyerang menebak password WS-ADM-03 sebanyak 200 kali dalam ~4 menit. | T1110 Brute Force |
| 21:05 | Salah satu tebakan berhasil: login sebagai `budi.s`. | T1078 Valid Accounts |
| 21:18 | Dengan akun itu, penyerang masuk ke SCADA-ENG-01 lewat remote desktop. | T1021 Remote Services |
| 21:25 | Dari SCADA-ENG-01, penyerang mengirim perintah Modbus: mengubah setpoint genset dari 50 Hz ke 25 Hz, lalu mematikan genset. | T0855, T0836, T0831 |

## Kenapa ini serangan, bukan kejadian biasa?
- Orang biasa salah password 1-2 kali. Ini 200 kali dalam beberapa menit.
- Perintah ke genset seharusnya hanya datang dari layar operator (SCADA-HMI-01), bukan dari komputer teknik.
- Nilai setpoint 25 Hz jauh dari normal (sekitar 50 Hz).

## Yang akan ditunjukkan alat kita
Sekitar 5.600 baris log -> 1 insiden dengan alur di atas -> ringkasan dan laporan Bahasa Indonesia.
