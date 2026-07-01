"""
Vercel Serverless Function: POST /api/analyze
Groq AI Analysis for Phishing Detection
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

        api_key = os.environ.get('GROQ_API_KEY', '')
        if not api_key:
            self._respond(200, {
                'ai_analysis': {'error': 'GROQ_API_KEY tidak ditemukan'},
                'url': url
            })
            return

        ai_result = groq_analyze(url, scan_result, api_key)
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


def groq_analyze(url: str, scan_result: dict, api_key: str) -> dict:
    verdict  = scan_result.get('verdict', 'UNKNOWN')
    score    = scan_result.get('score', 0)
    reasons  = scan_result.get('reasons', [])
    features = scan_result.get('features', {})

    reasons_text = '\n'.join(f'- {r}' for r in reasons) if reasons else '- Tidak ada indikator mencurigakan'

    prompt = f"""Kamu adalah seorang ahli keamanan siber senior yang menganalisis URL untuk mendeteksi phishing.

URL yang dianalisis: {url}

Hasil deteksi otomatis:
- Verdict: {verdict}
- Risk Score: {score}/100
- ML Score: {scan_result.get('ml_score', 0)}/100
- Heuristic Score: {scan_result.get('heuristic_score', 0)}/100

Indikator yang ditemukan:
{reasons_text}

Detail fitur URL:
- Panjang URL: {features.get('url_length', 0)} karakter
- Menggunakan HTTPS: {features.get('is_https', False)}
- Ada IP address: {features.get('has_ip', False)}
- TLD mencurigakan: {features.get('suspicious_tld', False)}
- Kata kunci phishing: {features.get('phishing_keywords', 0)} ditemukan

Berikan analisis dalam format JSON MURNI (tanpa markdown, langsung JSON):
{{
  "ringkasan": "Penjelasan singkat 1-2 kalimat tentang URL ini",
  "analisis_detail": "Analisis mendalam 3-5 kalimat menjelaskan mengapa URL ini berbahaya/aman, teknik phishing yang digunakan (jika ada), dan konteks ancamannya",
  "target_korban": "Siapa yang menjadi target serangan ini dan mengapa (jika phishing)",
  "tingkat_bahaya": "Penjelasan tingkat bahaya dalam 1-2 kalimat",
  "saran_tindakan": [
    "Saran tindakan 1",
    "Saran tindakan 2",
    "Saran tindakan 3",
    "Saran tindakan 4"
  ],
  "tanda_peringatan": [
    "Tanda peringatan utama 1",
    "Tanda peringatan utama 2",
    "Tanda peringatan utama 3"
  ],
  "kesimpulan": "Kesimpulan akhir dan rekomendasi utama dalam 1-2 kalimat"
}}"""

    try:
        payload = json.dumps({
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1500
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
            if text.startswith('```'):
                text = re.sub(r'^```[a-z]*\n?', '', text)
                text = re.sub(r'\n?```$', '', text)
            return json.loads(text.strip())
    except urllib.error.HTTPError as e:
        return {'error': f'Groq API error: HTTP {e.code}'}
    except json.JSONDecodeError as e:
        return {'error': f'Gagal parse respons Groq: {str(e)}'}
    except Exception as e:
        return {'error': f'Error: {str(e)}'}
