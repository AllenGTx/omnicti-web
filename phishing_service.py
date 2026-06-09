#!/usr/bin/env python3
"""
Phishing Detection Microservice - OmniCTI with Groq
Port: 5000 | POST /predict {"url": "..."}
              POST /analyze {"url": "...", "result": {}}

Pipeline:
  TF-IDF (5000) + 3 manual features → RandomForest → ML score
  + Heuristic rules → Heuristic score
  Final = 40% ML + 60% Heuristic
  
  AI Analysis: Groq API (Free LLM Cloud)
"""

import sys, json, re, os, warnings, urllib.request
warnings.filterwarnings('ignore')
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── Load ML Models ────────────────────────────────────────────────────────────
try:
    import joblib, numpy as np
    RF     = joblib.load('RandomForest_Phishing.joblib')
    TFIDF  = joblib.load('tfidf_phishing.joblib')
    SCALER = joblib.load('scaler_phishing.joblib')
    MODELS_LOADED = True
    print("[*] ML models loaded: RandomForest (100 trees) + TF-IDF + Scaler")
except Exception as e:
    MODELS_LOADED = False
    print(f"[!] ML models NOT loaded: {e}", file=sys.stderr)

# ── Constants ─────────────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    'login','signin','verify','account','secure','update','confirm','suspend',
    'banking','paypal','ebay','amazon','apple','microsoft','google','facebook',
    'password','credential','unusual','click','limited','urgent','free','prize',
    'winner','reward','bonus','wallet','invoice','alert','notification','reset',
]
SUSPICIOUS_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.link','.ru','.cn','.pw']

# ── Feature Extraction ────────────────────────────────────────────────────────
def extract_features(url: str) -> dict:
    low = url.lower()
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc
        path   = parsed.path
    except Exception:
        domain, path = url, ''
    return {
        'url_length'        : len(url),
        'num_dots'          : url.count('.'),
        'num_special'       : sum(1 for c in url if not c.isalnum()),
        'has_ip'            : bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
        'is_https'          : url.startswith('https'),
        'num_at'            : url.count('@'),
        'num_hyphens'       : url.count('-'),
        'suspicious_tld'    : any(t in low for t in SUSPICIOUS_TLDS),
        'phishing_keywords' : sum(1 for k in PHISHING_KEYWORDS if k in low),
        'subdomain_count'   : max(0, domain.replace('www.','').count('.')),
        'num_params'        : len(parse_qs(parsed.query)) if '?' in url else 0,
        'double_slash'      : '//' in url[8:],
    }

# ── Heuristic Scorer ──────────────────────────────────────────────────────────
def heuristic_score(url: str):
    f = extract_features(url)
    score, reasons = 0, []
    if f['has_ip']:
        score += 40; reasons.append('IP address digunakan sebagai domain (bukan nama domain)')
    if f['num_at'] > 0:
        score += 35; reasons.append('Simbol @ ditemukan di URL — teknik penyamaran domain')
    if f['suspicious_tld']:
        score += 35; reasons.append('TLD mencurigakan (.tk/.ml/.xyz/dll) — sering dipakai phisher')
    if f['phishing_keywords'] > 0:
        pts = min(30, f['phishing_keywords'] * 10)
        score += pts; reasons.append(f"Ditemukan {f['phishing_keywords']} kata kunci phishing dalam URL")
    if f['url_length'] > 75:
        score += 15; reasons.append(f"URL terlalu panjang ({f['url_length']} karakter)")
    if f['num_hyphens'] > 2:
        score += 10; reasons.append(f"Banyak tanda hubung ({f['num_hyphens']}) — ciri domain palsu")
    if f['num_dots'] > 4:
        score += 10; reasons.append(f"Banyak titik dalam URL ({f['num_dots']}) — kemungkinan domain palsu")
    if f['subdomain_count'] > 2:
        score += 10; reasons.append(f"Banyak subdomain ({f['subdomain_count']}) — pola domain tiruan")
    if f['double_slash']:
        score += 10; reasons.append('Double slash di tengah URL — teknik redirect berbahaya')
    if not f['is_https']:
        score += 8;  reasons.append('Tidak menggunakan HTTPS')
    if f['num_params'] > 4:
        score += 5;  reasons.append(f"Banyak parameter URL ({f['num_params']})")
    return min(100, score), reasons

# ── ML Scorer ─────────────────────────────────────────────────────────────────
def ml_score(url: str) -> float:
    if not MODELS_LOADED:
        return 0.0
    try:
        import numpy as np
        f   = extract_features(url)
        vec = TFIDF.transform([url]).toarray()
        sc  = SCALER.transform(np.array([[f['url_length'], f['num_dots'], f['num_special']]]))
        proba = RF.predict_proba(np.hstack([vec, sc]))[0][1]
        return min(100.0, round(proba * 300, 1))
    except Exception:
        return 0.0

# ── Main Predict ──────────────────────────────────────────────────────────────
def predict(url: str) -> dict:
    h_score, reasons = heuristic_score(url)
    m_score          = ml_score(url)
    f                = extract_features(url)

    final = round((m_score * 0.4) + (h_score * 0.6), 1) if MODELS_LOADED else float(h_score)
    final = min(100.0, final)

    if   final >= 35: verdict, level = 'PHISHING',   'danger'
    elif final >= 15: verdict, level = 'SUSPICIOUS',  'warning'
    else:             verdict, level = 'SAFE',         'safe'

    return {
        'url'             : url,
        'score'           : final,
        'ml_score'        : round(m_score, 1),
        'heuristic_score' : float(h_score),
        'verdict'         : verdict,
        'level'           : level,
        'reasons'         : reasons,
        'features'        : {
            'url_length'        : f['url_length'],
            'has_ip'            : f['has_ip'],
            'is_https'          : f['is_https'],
            'phishing_keywords' : f['phishing_keywords'],
            'num_dots'          : f['num_dots'],
            'num_hyphens'       : f['num_hyphens'],
            'suspicious_tld'    : f['suspicious_tld'],
            'subdomain_count'   : f['subdomain_count'],
        },
        'models_used'     : MODELS_LOADED,
    }

# ── Groq AI Analysis ──────────────────────────────────────────────────────────
def groq_analyze(url: str, scan_result: dict) -> dict:
    """Analyze using Groq Cloud LLM (Free)"""
    api_key = os.environ.get('GROQ_API_KEY', '')
    if not api_key:
        return {'error': 'GROQ_API_KEY tidak ditemukan. Set dengan: set GROQ_API_KEY=xxx'}

    verdict   = scan_result.get('verdict', 'UNKNOWN')
    score     = scan_result.get('score', 0)
    reasons   = scan_result.get('reasons', [])
    features  = scan_result.get('features', {})

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
            "model": "mixtral-8x7b-32768",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1024
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

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            text = data['choices'][0]['message']['content']
            text = text.strip()
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

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self.send_error(400, 'Invalid JSON'); return

        if self.path == '/predict':
            url = data.get('url', '').strip()
            if not url: self.send_error(400, 'URL required'); return
            result = predict(url)
            self._respond(result)

        elif self.path == '/analyze':
            url    = data.get('url', '').strip()
            result = data.get('result', {})
            if not url: self.send_error(400, 'URL required'); return
            if not result:
                result = predict(url)
            ai = groq_analyze(url, result)
            self._respond({'ai_analysis': ai, 'url': url})

        else:
            self.send_error(404)

    def _respond(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(body)

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PHISHING_PORT', 5001))
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f"[*] Phishing Detection Service → http://0.0.0.0:{port}")
    print(f"[*] Model: {'RandomForest 100 trees + TF-IDF 5000 features' if MODELS_LOADED else 'Heuristic only'}")
    groq_key = os.environ.get('GROQ_API_KEY', '')
    print(f"[*] Groq AI: {'✓ Ready' if groq_key else '✗ GROQ_API_KEY not set'}")
    server.serve_forever()
