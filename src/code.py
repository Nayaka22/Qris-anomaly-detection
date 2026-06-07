import matplotlib.pyplot as plt

# --- KONFIGURASI DAN AMBANG BATAS ---
MAX_VELOCITY = 3          # Batas frekuensi transaksi user (D&C)
BATAS_NOMINAL = 1000000    # Batas nominal ekstrem Rp 1 juta
MALWARE_KEYWORD = "DEV_MALWARE"  # Pattern string untuk Rabin-Karp

# Pembobotan skor berdasarkan kriteria instansi
SKOR_RK = 50       # Cek blacklist device
SKOR_VELO = 35     # Cek velocity attack
SKOR_NOMINAL = 15  # Cek nominal jumbo

KUOTA_HARIAN = 3   # Slot maksimal investigasi (Greedy capacity)


# --- DATASET SIMULASI LOG TRANSAKSI QRIS ---
dataset_qris = [
    {"id_tx": "TX001", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 50000, "skor": 0},
    {"id_tx": "TX002", "user": "Budi",   "device": "DEV_SAMSUNG_01", "amount": 15000, "skor": 0},
    {"id_tx": "TX003", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 45000, "skor": 0}, 
    {"id_tx": "TX004", "user": "Siti",   "device": "DEV_XIAOMI_99",  "amount": 2500000, "skor": 0}, 
    {"id_tx": "TX005", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 60000, "skor": 0}, 
    {"id_tx": "TX006", "user": "Andi",   "device": "DEV_MALWARE_X",  "amount": 25000, "skor": 0}, 
    {"id_tx": "TX007", "user": "Budi",   "device": "DEV_SAMSUNG_01", "amount": 30000, "skor": 0},
    {"id_tx": "TX008", "user": "Siti",   "device": "DEV_XIAOMI_99",  "amount": 1500000, "skor": 0}, 
]


# ==============================================================================
# FUNGSI ALGORITMA

# 1. Algoritma Rabin-Karp (Pattern Matching)
def pencocokan_rabin_karp(text, pattern):
    d = 256     
    q = 1000003 # Pakai prima besar biar gak gampang kolisi (spurious hits)
    m = len(pattern)
    n = len(text)
    p = 0       
    t = 0       
    h = 1

    if m > n: 
        return False

    for i in range(m - 1):
        h = (h * d) % q

    for i in range(m):
        p = (d * p + ord(pattern[i])) % q
        t = (d * t + ord(text[i])) % q

    for i in range(n - m + 1):
        if p == t:
            cocok = True
            for j in range(m):
                if text[i + j] != pattern[j]:
                    cocok = False
                    break
            if cocok: 
                return True

        if i < n - m:
            t = (d * (t - ord(text[i]) * h) + ord(text[i + m])) % q
            if t < 0: 
                t = t + q
    return False


# 2. Algoritma Divide and Conquer (Hitung Frekuensi Global - Pre-processing O(n))
def hitung_frekuensi_dc(data):
    # Base case kalau array kosong atau cuma 1 elemen
    if len(data) == 0:
        return {}
    if len(data) == 1:
        return {data[0]["user"]: 1}

    # Tahap Divide: Bagi data jadi dua kelompok (kiri & kanan)
    tengah = len(data) // 2
    peta_kiri = hitung_frekuensi_dc(data[:tengah])
    peta_kanan = hitung_frekuensi_dc(data[tengah:])

    # Tahap Combine: Gabungin hasil hitungan kamus kiri dan kanan
    hasil_gabungan = peta_kiri.copy()
    for user, jumlah in peta_kanan.items():
        if user in hasil_gabungan:
            hasil_gabungan[user] += jumlah
        else:
            hasil_gabungan[user] = jumlah
            
    return hasil_gabungan


# 3. Strategi Greedy dengan Fitur Pemutus Seri / Tie-Breaking
def seleksi_greedy_kasus(data, kuota):
    # Urutkan multi-level: Prioritas utama berdasarkan skor (DESC), 
    # kalau skor seri diurutkan berdasarkan amount/nominal terbesar (DESC)
    data_terurut = sorted(data, key=lambda x: (x["skor"], x["amount"]), reverse=True)
    
    kasus_terpilih = []
    for i in range(min(kuota, len(data_terurut))):
        if data_terurut[i]["skor"] > 0:
            kasus_terpilih.append(data_terurut[i])
            
    return kasus_terpilih



# PIPELINE PROSES UTAMA

print("--- PROSES PEMERIKSAAN FRAUD TRANSAKSI QRIS ---\n")

# Jalankan fungsi D&C satu kali di awal biar performa tetap O(n) murni
map_frekuensi = hitung_frekuensi_dc(dataset_qris)

for tx in dataset_qris:
    # Kriteria 1: Cek kecocokan string device dengan Rabin-Karp
    if pencocokan_rabin_karp(tx["device"], MALWARE_KEYWORD):
        tx["skor"] += SKOR_RK
        print(f"[ALERT] {tx['id_tx']} - Device masuk blacklist ({tx['device']}). Skor +{SKOR_RK}")

    # Kriteria 2: Cek frekuensi transaksi dari hasil Divide & Conquer
    total_tx_user = map_frekuensi.get(tx["user"], 0)
    if total_tx_user >= MAX_VELOCITY:
        tx["skor"] += SKOR_VELO
        print(f"[ALERT] {tx['id_tx']} - Indikasi Velocity Attack! User '{tx['user']}' transaksi {total_tx_user}x. Skor +{SKOR_VELO}")

    # Kriteria 3: Validasi nilai nominal transaksi
    if tx["amount"] > BATAS_NOMINAL:
        tx["skor"] += SKOR_NOMINAL
        print(f"[ALERT] {tx['id_tx']} - Nominal Rp {tx['amount']} melampaui batas wajar. Skor +{SKOR_NOMINAL}")

# Alokasi penanganan kasus kritis dengan Greedy
investigasi_hari_ini = seleksi_greedy_kasus(dataset_qris, KUOTA_HARIAN)

print(f"\n--- REKOMENDASI KASUS PRIORITAS (Maksimal Slot: {KUOTA_HARIAN}) ---")
for urutan, item in enumerate(investigasi_hari_ini, start=1):
    print(f"Peringkat {urutan}: {item['id_tx']} | User: {item['user']} | Nominal: Rp {item['amount']} | Total Skor: {item['skor']}")


#
# PLOTTING GRAFIK EVALUASI

list_id = [tx["id_tx"] for tx in dataset_qris]
list_skor = [tx["skor"] for tx in dataset_qris]

id_prioritas = [k["id_tx"] for k in investigasi_hari_ini]
pilihan_warna = ['#e74c3c' if item_id in id_prioritas else '#3498db' for item_id in list_id]

plt.figure(figsize=(9, 5.5))
batang = plt.bar(list_id, list_skor, color=pilihan_warna, edgecolor='black', zorder=3)

plt.title("Analisis Komparasi Risiko Transaksi QRIS\n(Batang Merah = Kasus Prioritas Utama Hasil Seleksi Greedy)", fontsize=12, fontweight='bold')
plt.xlabel("ID Transaksi", fontsize=10)
plt.ylabel("Skor Risiko (0 - 100)", fontsize=10)
plt.ylim(0, 100)
plt.grid(axis='y', linestyle='--', alpha=0.5, zorder=0)

# Tampilin angka skor di atas batang grafiknya
for b in batang:
    tinggi = b.get_height()
    if tinggi > 0:
        plt.text(b.get_x() + b.get_width()/2.0, tinggi + 2, f"{tinggi}", ha='center', va='bottom', fontweight='bold')

plt.tight_layout()
plt.show()