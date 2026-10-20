"""
Test the local model with the SHORT summary-only prompt.
    python scripts/test_ollama.py
    python scripts/test_ollama.py qwen2.5:1.5b
"""
import json
import sys
import time
import urllib.request

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:3b"

PROMPT = """Tulis ringkasan insiden keamanan siber dalam Bahasa Indonesia formal.
Aturan: 3 sampai 4 kalimat, hanya berdasarkan data di bawah, jangan menambah fakta,
jangan memberi rekomendasi.

Data:
- 21:00 | 200 login gagal ke WS-ADM-03 dari 10.10.5.23 (Brute Force)
- 21:05 | Login berhasil akun budi.s dari IP yang sama (Valid Accounts)
- 21:20 | budi.s terhubung ke server kontrol genset GEN-CTRL-01 (Remote Services)
- 21:25 | Perintah Modbus mengubah setpoint dan mematikan genset (Unauthorized Command Message)
"""

body = json.dumps({
    "model": MODEL,
    "prompt": PROMPT,
    "stream": False,
    "keep_alive": "30m",                      # keep model in RAM
    "options": {"temperature": 0.2, "num_predict": 160},  # steady + short
}).encode()

req = urllib.request.Request(
    "http://localhost:11434/api/generate",
    data=body,
    headers={"Content-Type": "application/json"},
)

print(f"Model: {MODEL} ...\n")
start = time.time()
with urllib.request.urlopen(req, timeout=300) as resp:
    print(json.loads(resp.read())["response"])
print(f"\n--- took {time.time() - start:.1f} seconds ---")