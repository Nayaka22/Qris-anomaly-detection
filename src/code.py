import matplotlib.pyplot as plt

# ==============================================================================
# 1. PARAMETER SISTEM & KONFIGURASI THRESHOLD (LOGIKA BISNIS)
# ==============================================================================
THRESHOLD_VELOCITY_COUNT = 3        # Maksimal frekuensi transaksi (Konieks: D&C)
THRESHOLD_NOMINAL_EKSTREM = 1000000  # Batas nominal wajar Rp 1.000.000
BLACKLIST_PATTERN = "DEV_MALWARE"    # Pola string perangkat fraud (Konieks: Rabin-Karp)

# Pembobotan Skor Risiko (Risk Scoring Matrix)
BOBOT_RABIN_KARP = 50   # Signatures/perangkat terlarang
BOBOT_VELOCITY = 35     # Indikasi flooding/velocity attack
BOBOT_NOMINAL = 15      # Lonjakan nominal ekstrem

# Slot kuota penanganan harian oleh investigator (Bounded Capacity)
SLOT_INVESTIGASI_HARIAN = 3

# ==============================================================================
# 2. DATASET SIMULASI (DATA LOG TRANSAKSI QRIS)
# ==============================================================================
dataset_qris = [
    {"tx_id": "TX001", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 50000, "risk_score": 0},
    {"tx_id": "TX002", "user": "Budi",   "device": "DEV_SAMSUNG_01", "amount": 15000, "risk_score": 0},
    {"tx_id": "TX003", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 45000, "risk_score": 0}, 
    {"tx_id": "TX004", "user": "Siti",   "device": "DEV_XIAOMI_99",  "amount": 2500000, "risk_score": 0}, # Melanggar THRESHOLD_NOMINAL_EKSTREM
    {"tx_id": "TX005", "user": "Nayaka", "device": "DEV_IPHONE_77", "amount": 60000, "risk_score": 0}, # Skor 35, nominal tertinggi di antara kelompok 'Nayaka'
    {"tx_id": "TX006", "user": "Andi",   "device": "DEV_MALWARE_X",  "amount": 25000, "risk_score": 0}, # Melanggar BLACKLIST_PATTERN
    {"tx_id": "TX007", "user": "Budi",   "device": "DEV_SAMSUNG_01", "amount": 30000, "risk_score": 0},
    {"tx_id": "TX008", "user": "Siti",   "device": "DEV_XIAOMI_99",  "amount": 1500000, "risk_score": 0}, # Melanggar THRESHOLD_NOMINAL_EKSTREM
]

# ==============================================================================
# 3. IMPLEMENTASI ALGORITMA PARADIGMA KLASIK (OPTIMIZED)
# ==============================================================================

# --- [A] PARADIGMA 1: STRING MATCHING (RABIN-KARP O(n+m)) ---
# Referensi Teoretis: Karp & Rabin (1987)
def rabin_karp_search(text, pattern):
    d = 256     
    q = 1000003 # Nilai prima ditingkatkan untuk skala industri mendeteksi anomali tanpa kolisi hash
    m = len(pattern)
    n = len(text)
    p = 0       
    t = 0       
    h = 1

    if m > n: return False

    for i in range(m - 1):
        h = (h * d) % q

    for i in range(m):
        p = (d * p + ord(pattern[i])) % q
        t = (d * t + ord(text[i])) % q

    for i in range(n - m + 1):
        if p == t:
            match = True
            for j in range(m):
                if text[i + j] != pattern[j]:
                    match = False
                    break
            if match: return True

        if i < n - m:
            t = (d * (t - ord(text[i]) * h) + ord(text[i + m])) % q
            if t < 0: t = t + q
    return False


# --- [B] PARADIGMA 2: DIVIDE AND CONQUER FREQUENCY MAP (O(n)) ---
# Referensi Teoretis: Cormen et al. (2009) - Pendekatan Global MapReduce Rekursif
def build_frequency_map_dc(data):
    # Base Case 1: Array Kosong
    if len(data) == 0:
        return {}
    # Base Case 2: Array Tunggal (Conquer)
    if len(data) == 1:
        return {data[0]["user"]: 1}

    # Divide: Memotong data log menjadi dua bagian setara
    mid = len(data) // 2
    left_map = build_frequency_map_dc(data[:mid])
    right_map = build_frequency_map_dc(data[mid:])

    # Combine: Menggabungkan kamus frekuensi dari sub-masalah kiri dan kanan
    combined_map = left_map.copy()
    for user, count in right_map.items():
        if user in combined_map:
            combined_map[user] += count
        else:
            combined_map[user] = count
            
    return combined_map


# --- [C] PARADIGMA 3: STRATEGI GREEDY DENGAN TIE-BREAKING (O(n log n)) ---
# Referensi Teoretis: Kleinberg & Tardos (2005) - Berbasis Multi-Criterion Sorting
def greedy_fraud_selection_optimized(data, max_slots):
    # Urutkan berdasarkan Kriteria Utama (risk_score DESC), lalu Kriteria Kedua (amount DESC) jika skor risiko seri
    # Ini adalah implementasi formal penanganan Tie-Breaking pada Strategi Greedy
    sorted_data = sorted(data, key=lambda x: (x["risk_score"], x["amount"]), reverse=True)
    
    selected_anomalies = []
    for i in range(min(max_slots, len(sorted_data))):
        if sorted_data[i]["risk_score"] > 0:
            selected_anomalies.append(sorted_data[i])
            
    return selected_anomalies

# ==============================================================================
# 4. PIPELINE EKSEKUSI & EVALUASI DATA TRANSAKSI
# ==============================================================================
print("=== MEMULAI PIPELINE EVALUASI RISIKO TRANSAKSI QRIS (FIX OPTIMIZED) ===\n")

# Eksekusi Divide and Conquer SATU KALI di awal untuk performa O(n) murni
frequency_map = build_frequency_map_dc(dataset_qris)

for tx in dataset_qris:
    # Aturan 1: Pemindaian Tekstual Perangkat Menggunakan Rabin-Karp
    if rabin_karp_search(tx["device"], BLACKLIST_PATTERN):
        tx["risk_score"] += BOBOT_RABIN_KARP
        print(f"[ALERT RABIN-KARP] {tx['tx_id']} - Perangkat terindikasi Blacklist Pattern ({tx['device']}). Skor +{BOBOT_RABIN_KARP}")

    # Aturan 2: Pencocokan Frekuensi Hasil Olahan D&C Map
    frekuensi = frequency_map.get(tx["user"], 0)
    if frekuensi >= THRESHOLD_VELOCITY_COUNT:
        tx["risk_score"] += BOBOT_VELOCITY
        print(f"[ALERT DIVIDE & CONQUER] {tx['tx_id']} - Defisit Velocity! User '{tx['user']}' bertransaksi {frekuensi}x. Skor +{BOBOT_VELOCITY}")

    # Aturan 3: Validasi Batas Nominal Finansial
    if tx["amount"] > THRESHOLD_NOMINAL_EKSTREM:
        tx["risk_score"] += BOBOT_NOMINAL
        print(f"[ALERT AMBANG NOMINAL] {tx['tx_id']} - Nominal Rp {tx['amount']} melewati ambang batas Rp {THRESHOLD_NOMINAL_EKSTREM}. Skor +{BOBOT_NOMINAL}")

# Lapisan Pengambilan Keputusan Akhir Menggunakan Strategi Greedy Teroptimasi
kasus_kritis = greedy_fraud_selection_optimized(dataset_qris, SLOT_INVESTIGASI_HARIAN)

print(f"\n=== HASIL SELEKSI OPTIMAL GREEDY (Slot Maksimal: {SLOT_INVESTIGASI_HARIAN}) ===")
for idx, kasus in enumerate(kasus_kritis, start=1):
    print(f"Peringkat {idx}: {kasus['tx_id']} | User: {kasus['user']} | Nominal: Rp {kasus['amount']} | Total Skor Risiko: {kasus['risk_score']}")

# ==============================================================================
# 5. VISUALISASI MATPLOTLIB (BAHAN GRAFIK MAKALAH)
# ==============================================================================
tx_ids = [tx["tx_id"] for tx in dataset_qris]
skor_risiko = [tx["risk_score"] for tx in dataset_qris]

id_kasus_kritis = [k["tx_id"] for k in kasus_kritis]
warna_batang = ['#e74c3c' if tx_id in id_kasus_kritis else '#3498db' for tx_id in tx_ids]

plt.figure(figsize=(10, 6))
bars = plt.bar(tx_ids, skor_risiko, color=warna_batang, edgecolor='black', zorder=3)

plt.title("Analisis Komparasi Tingkat Risiko Transaksi QRIS (Optimized)\n(Merah = Kasus Kritis Prioritas Hasil Pilihan Algoritma Greedy)", fontsize=13, fontweight='bold')
plt.xlabel("ID Transaksi Digital (QRIS)", fontsize=11)
plt.ylabel("Total Skor Risiko (Risk Score Scale 0-100)", fontsize=11)
plt.ylim(0, 100)
plt.grid(axis='y', linestyle='--', alpha=0.7, zorder=0)

for bar in bars:
    yval = bar.get_height()
    if yval > 0:
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 2, f"{yval}", ha='center', va='bottom', fontweight='bold')

plt.tight_layout()
plt.show()