# Menjalankan dengan Docker (satu perintah)

Syarat: Docker Desktop berjalan, Ollama terpasang di komputer yang sama dengan model `qwen2.5:3b`.

## Pertama kali (butuh internet sekali, untuk mengunduh image)
```
cd D:\cyber-triage
docker compose up --build
```
Tunggu sampai muncul tulisan Uvicorn running dan Next.js ready. Lalu buka http://localhost:3000

## Sehari-hari
- Jalankan:  `docker compose up`   (tambah `-d` untuk berjalan di latar belakang)
- Hentikan:  `docker compose down`
- Setelah mengganti `backend/data/mitre_map.csv`:  `docker compose restart backend`
  (`playbook.csv` langsung terbaca tanpa restart.)
- Setelah mengubah kode:  `docker compose up --build`

## Dipindah ke komputer lain tanpa internet
Di komputer yang punya internet:
```
docker compose build
docker save -o cyber-triage-images.tar cyber-triage-backend cyber-triage-frontend
```
Salin file tar + folder proyek ke komputer tujuan, lalu:
```
docker load -i cyber-triage-images.tar
docker compose up
```
(Nama image bisa berbeda; cek dengan `docker images`.) Ollama dan modelnya harus dipasang terpisah di komputer tujuan.

## Jika ringkasan AI selalu berisi template (Ollama tidak terjangkau dari Docker)
Setel Ollama agar menerima koneksi dari Docker, lalu mulai ulang Ollama:
```
setx OLLAMA_HOST "0.0.0.0"
```

## Jika RAM 8GB terasa penuh
Batasi memori WSL2: buat file `C:\Users\NAMAMU\.wslconfig` berisi
```
[wsl2]
memory=3GB
```
lalu jalankan `wsl --shutdown` dan buka ulang Docker Desktop.
