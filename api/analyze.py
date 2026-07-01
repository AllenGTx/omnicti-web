"""
Vercel Serverless Function: POST /api/analyze
AI Analysis for Phishing Detection via HuggingFace Inference API
"""

import json
import os
import re
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler

# ── Vercel Handler ────────────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._respond(400, {'error': 'Invalid JSON'})
            return

        url = data.get('url', '').strip()
        if not url:
            self._respond(400, {'error': 'url is required'})
            return

        scan_result = data.get('result', {})

        # Try Groq first, fallback to HuggingFace, then rule-based
        groq_key = os.environ.get('GROQ_API_KEY', '')
        hf_key   = os.environ.get('HF_TOKEN', os.environ.get('HUGGINGFACE_TOKEN', ''))

        ai_result = None

        # Try Groq if key looks valid
        if groq_key and groq_key.startswith('gsk_'):
            result = groq_analyze(url, scan_result, groq_key)
            if 'error' not in result:
                ai_result = result
            # else: fall through to HF

        # Try HuggingFace if Groq failed or not configured
        if ai_result is None and hf_key:
            result = hf_analyze(url, scan_result, hf_key)
            if 'error' not in result:
                ai_result = result

        # Always-available fallback
        if ai_result is None:
            ai_result = rule_based_analyze(url, scan_result)

        self._respond(200, {'ai_analysis': ai_result, 'url': url})

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _respond(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(body)


def build_prompt(url: str, scan_result: dict) -> str:
    verdict  = scan_result.get('verdict', 'UNKNOWN')
    score    = scan_result.get('score', 0)
    reasons  = scan_result.get('reasons', [])
    features = scan_result.get('features', {})
    reasons_text = '\n'.join(f'- {r}' for r in reasons) if reasons else '- Tidak ada indikator mencurigakan'

    return f"""Kamu adalah ahli keamanan siber. Analisis URL berikut untuk mendeteksi phishing.

URL: {url}
Verdict: {verdict} | Risk Score: {score}/100
Indikator: {reasons_text}
Fitur: HTTPS={features.get('is_https',False)}, IP={features.get('has_ip',False)}, TLD_suspicious={features.get('suspicious_tld',False)}, keywords={features.get('phishing_keywords',0)}

Berikan analisis dalam format JSON MURNI (tanpa markdown):
{{
  "ringkasan": "Penjelasan singkat 1-2 kalimat",
  "analisis_detail": "Analisis mendalam 3-5 kalimat",
  "target_korban": "Siapa target (jika phishing)",
  "tingkat_bahaya": "Penjelasan tingkat bahaya 1-2 kalimat",
  "saran_tindakan": ["Saran 1", "Saran 2", "Saran 3"],
  "tanda_peringatan": ["Peringatan 1", "Peringatan 2"],
  "kesimpulan": "Kesimpulan akhir 1-2 kalimat"
}}"""


def groq_analyze(url: str, scan_result: dict, api_key: str) -> dict:
    prompt = build_prompt(url, scan_result)
    try:
        payload = json.dumps({
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1000
        }).encode('utf-8')

        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            resp_data = json.loads(resp.read().decode('utf-8'))
            text = resp_data['choices'][0]['message']['content'].strip()
            text = re.sub(r'^```[a-z]*\n?', '', text)
            text = re.sub(r'\n?```$', '', text)
            return json.loads(text.strip())
    except urllib.error.HTTPError as e:
        return {'error': f'Groq API error: HTTP {e.code}'}
    except Exception as e:
        return {'error': f'Groq error: {str(e)}'}


def hf_analyze(url: str, scan_result: dict, api_key: str) -> dict:
    """Use HuggingFace Inference API (Mistral-7B)"""
    prompt = build_prompt(url, scan_result)
    try:
        payload = json.dumps({
            "inputs": f"<s>[INST] {prompt} [/INST]",
            "parameters": {
                "max_new_tokens": 800,
                "temperature": 0.3,
                "return_full_text": False
            }
        }).encode('utf-8')

        req = urllib.request.Request(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = json.loads(resp.read().decode('utf-8'))
            # HF returns list of generated texts
            if isinstance(resp_data, list) and resp_data:
                text = resp_data[0].get('generated_text', '')
            else:
                text = str(resp_data)

            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                return json.loads(json_match.group())
            return {'error': 'Gagal parse respons HF', 'raw': text[:200]}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')[:300]
        return {'error': f'HuggingFace API error: HTTP {e.code} - {body}'}
    except Exception as e:
        return {'error': f'HuggingFace error: {str(e)}'}


def rule_based_analyze(url: str, scan_result: dict) -> dict:
    """Fallback: rule-based analysis when no AI key is available"""
    verdict  = scan_result.get('verdict', 'UNKNOWN')
    score    = scan_result.get('score', 0)
    reasons  = scan_result.get('reasons', [])
    features = scan_result.get('features', {})

    if score >= 70 or verdict == 'PHISHING':
        ringkasan = f"URL ini terdeteksi sebagai PHISHING dengan skor risiko {score}/100."
        analisis  = (
            f"Sistem mendeteksi {len(reasons)} indikator mencurigakan pada URL ini. "
            f"{'URL menggunakan IP langsung yang umum pada phishing. ' if features.get('has_ip') else ''}"
            f"{'TLD yang digunakan bukan TLD umum. ' if features.get('suspicious_tld') else ''}"
            f"{'Ditemukan kata kunci phishing umum. ' if features.get('phishing_keywords',0)>0 else ''}"
            "Kami sangat menyarankan untuk tidak mengunjungi URL ini."
        )
        saran = [
            "Jangan klik atau bagikan URL ini",
            "Laporkan ke Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/",
            "Jika sudah terlanjur mengunjungi, segera ganti password",
            "Aktifkan 2FA pada akun yang mungkin terdampak"
        ]
        bahaya = "Tingkat bahaya TINGGI. URL ini menunjukkan banyak ciri-ciri phishing."
        kesimpulan = "Hindari URL ini sepenuhnya dan laporkan ke pihak berwenang."
    elif score >= 30:
        ringkasan = f"URL ini mencurigakan dengan skor risiko {score}/100 dan memerlukan verifikasi lebih lanjut."
        analisis  = f"Terdapat {len(reasons)} indikator yang perlu diwaspadai. Lakukan verifikasi sebelum memasukkan data apapun."
        saran = ["Verifikasi keaslian URL sebelum login", "Cek sertifikat SSL", "Hubungi sumber resmi secara langsung"]
        bahaya = "Tingkat bahaya SEDANG. Berhati-hati sebelum berinteraksi dengan URL ini."
        kesimpulan = "Waspada dan lakukan verifikasi lebih lanjut sebelum menggunakan URL ini."
    else:
        ringkasan = f"URL ini tampak aman dengan skor risiko {score}/100."
        analisis  = "Tidak ditemukan indikator phishing yang signifikan. URL menggunakan HTTPS dan tidak menunjukkan pola mencurigakan."
        saran = ["Tetap waspada saat memasukkan data sensitif", "Pastikan Anda mengunjungi situs yang benar"]
        bahaya = "Tingkat bahaya RENDAH berdasarkan analisis otomatis."
        kesimpulan = "URL ini tampak aman, namun tetap berhati-hati."

    return {
        "ringkasan": ringkasan,
        "analisis_detail": analisis,
        "target_korban": "Pengguna umum yang tidak waspada terhadap URL phishing." if score >= 70 else "Tidak ada target spesifik teridentifikasi.",
        "tingkat_bahaya": bahaya,
        "saran_tindakan": saran,
        "tanda_peringatan": reasons[:3] if reasons else ["Tidak ada tanda peringatan terdeteksi"],
        "kesimpulan": kesimpulan,
        "_source": "rule-based (no AI key)"
    }
