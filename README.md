# 🛡️ OmniCTI Security Suite

OmniCTI Security Suite adalah platform intelijen ancaman siber (*Cyber Threat Intelligence*) all-in-one yang dirancang untuk menganalisis risiko keamanan domain dan mendeteksi tautan *phishing* secara cerdas dan real-time.

🌐 **Live Demo (Vercel)**: [https://omnicti-web.vercel.app/](https://omnicti-web.vercel.app/)

---

## ✨ Fitur Utama

### 1. 🔍 Web Domain Checker (Attack Surface & Threat Intelligence)
Fitur analisis menyeluruh untuk memetakan postur keamanan dan risiko domain publik:
- **Multi-Source Threat Intelligence**: Mengagregasi data EASM (*External Attack Surface Management*) dari berbagai sumber reputasi dan intelijen ancaman terkemuka seperti Shodan, Censys, LeakIX, VirusTotal, AlienVault OTX, AbuseIPDB, IPinfo, dan ThreatBook.
- **AI-Powered Risk Assessment**: Menggunakan LLM (Gemini dengan fallback Groq Llama 3) untuk menghasilkan analisis risiko eksekutif kontekstual, estimasi dampak, dan rekomendasi perbaikan teknis (*Remediation Roadmap*).
- **Comprehensive Risk Scoring**: Menghitung skor risiko gabungan (0–100) berdasarkan temuan celah keamanan, port terbuka, dan riwayat ancaman.

### 2. 🎣 Phishing Detector (URL & Link Scanner)
Mesin deteksi tautan phishing canggih berlapis untuk melindungi pengguna dari kejahatan rekayasa sosial:
- **Heuristic & Pattern Detection**: Menganalisis struktur URL, entropi karakter, penggunaan IP langsung, double slash, hingga kata kunci phishing spesifik.
- **IDN Homograph & Punycode Detection**: Mendeteksi domain palsu yang memanfaatkan karakter Unicode serupa/menipu (contoh: `xn--pypal-4ve.com`).
- **Typosquatting Detection**: Algoritma cerdas berbasis *Levenshtein Distance* untuk menangkap peniruan merek populer (seperti `paypa1.com`, `g00gle.com`, dll.).
- **Redirection & Shortener Detection**: Melacak pola URL shortener dan open redirect yang sering disalahgunakan untuk menyembunyikan situs phishing.

---

## 🚀 Live Deployment

- **Web App (Vercel)**: [https://omnicti-web.vercel.app/](https://omnicti-web.vercel.app/)
- **Backend / Engine (Hugging Face Space)**: [https://allengt-omnicti.hf.space](https://allengt-omnicti.hf.space)

---

## 🛠️ Teknologi

- **Backend**: Go (Golang) & Python Serverless Functions
- **Frontend**: HTML5, Tailwind CSS, JavaScript (Responsive Mobile & Desktop)
- **AI Engine**: Google Gemini API & Groq API
- **Deployment**: Vercel & Hugging Face Spaces (Docker)

---

## 🔒 Lisensi & Disclaimer

Aplikasi ini ditujukan untuk tujuan edukasi, penelitian keamanan siber, dan pertahanan proaktif organisasi. Gunakan dengan bijak sesuai etika dan regulasi keamanan informasi yang berlaku.
