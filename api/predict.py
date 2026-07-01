"""
Vercel Serverless Function: POST /api/predict
Phishing Detection via ML (RandomForest + TF-IDF) + Heuristic
"""

import json
import re
import os
import warnings
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler

warnings.filterwarnings('ignore')

# ── Resolve model paths (relative to this file's directory) ──────────────────
_ROOT = Path(__file__).parent.parent
_MODEL_RF     = _ROOT / "RandomForest_Phishing.joblib"
_MODEL_TFIDF  = _ROOT / "tfidf_phishing.joblib"
_MODEL_SCALER = _ROOT / "scaler_phishing.joblib"

# ── Load ML Models ────────────────────────────────────────────────────────────
try:
    import joblib
    import numpy as np
    RF     = joblib.load(_MODEL_RF)
    TFIDF  = joblib.load(_MODEL_TFIDF)
    SCALER = joblib.load(_MODEL_SCALER)
    MODELS_LOADED = True
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

BRAND_DOMAINS = {
    'klikbca':   ['klikbca.com'],
    'bca':       ['klikbca.com', 'bca.co.id', 'mybca.bca.co.id'],
    'mandiri':   ['bankmandiri.co.id', 'mandiri.co.id', 'livinbymandiri.co.id'],
    'livin':     ['bankmandiri.co.id', 'mandiri.co.id'],
    'bni':       ['bni.co.id', 'bnidirect.bni.co.id'],
    'bri':       ['bri.co.id', 'internet-banking.bri.co.id', 'briva.id'],
    'brimo':     ['bri.co.id'],
    'cimb':      ['cimbniaga.co.id', 'cimbniaga.com', 'octo.cimbniaga.co.id'],
    'danamon':   ['danamon.co.id', 'danamon.com'],
    'permata':   ['permatabank.com', 'permatamobile.com'],
    'btpn':      ['btpn.com', 'jenius.com'],
    'jenius':    ['jenius.com', 'btpn.com'],
    'gopay':     ['gojek.com', 'gopay.co.id'],
    'ovo':       ['ovo.id'],
    'dana':      ['dana.id'],
    'linkaja':   ['linkaja.id'],
    'flip':      ['flip.id'],
    'bibit':     ['bibit.id'],
    'paypal':    ['paypal.com'],
    'visa':      ['visa.com', 'visa.co.id'],
    'mastercard':['mastercard.com'],
    'apple':     ['apple.com', 'icloud.com', 'appleid.apple.com'],
    'icloud':    ['icloud.com', 'apple.com'],
    'google':    ['google.com', 'gmail.com', 'youtube.com', 'google.co.id'],
    'gmail':     ['gmail.com', 'google.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'office365.com'],
    'amazon':    ['amazon.com', 'amazon.co.id', 'amazonaws.com'],
    'netflix':   ['netflix.com'],
    'facebook':  ['facebook.com', 'fb.com', 'messenger.com'],
    'instagram': ['instagram.com'],
    'whatsapp':  ['whatsapp.com', 'wa.me'],
    'tiktok':    ['tiktok.com'],
    'tokopedia': ['tokopedia.com'],
    'shopee':    ['shopee.co.id', 'shopee.com'],
    'gojek':     ['gojek.com', 'goto.id'],
    'grab':      ['grab.com', 'grab.co.id'],
    'traveloka': ['traveloka.com'],
    'bukalapak': ['bukalapak.com'],
    'lazada':    ['lazada.co.id', 'lazada.com'],
    'blibli':    ['blibli.com'],
    'tiket':     ['tiket.com'],
    'telkomsel': ['telkomsel.com', 'mytelkomsel.com'],
    'indosat':   ['indosatooredoo.com', 'ioh.co.id'],
    'pertamina': ['pertamina.com', 'mypertamina.id'],
    'mypertamina':['mypertamina.id', 'pertamina.com'],
}

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
    if f['phishing_keywords'] >= 2:
        pts = min(25, (f['phishing_keywords'] - 1) * 7)
        score += pts; reasons.append(f"Ditemukan {f['phishing_keywords']} kata kunci phishing dalam URL")
    if f['url_length'] > 100:
        score += 10; reasons.append(f"URL sangat panjang ({f['url_length']} karakter)")
    if f['num_hyphens'] > 3:
        score += 8; reasons.append(f"Banyak tanda hubung ({f['num_hyphens']}) — ciri domain palsu")
    if f['num_dots'] > 5:
        score += 8; reasons.append(f"Banyak titik dalam URL ({f['num_dots']}) — kemungkinan domain palsu")
    if f['subdomain_count'] > 3:
        score += 8; reasons.append(f"Banyak subdomain ({f['subdomain_count']}) — pola domain tiruan")
    if f['double_slash']:
        score += 10; reasons.append('Double slash di tengah URL — teknik redirect berbahaya')
    if not f['is_https']:
        score += 5;  reasons.append('Tidak menggunakan HTTPS')
    if f['num_params'] > 5:
        score += 5;  reasons.append(f"Banyak parameter URL ({f['num_params']})")

    # ── Brand impersonation / typosquatting check ──────────────────────────────
    try:
        parsed_bd = urlparse(url if '://' in url else 'http://' + url)
        raw_domain = re.sub(r'^www\.', '', parsed_bd.netloc.lower()).split(':')[0]
        for brand, official_list in BRAND_DOMAINS.items():
            if brand in raw_domain:
                is_official = any(
                    raw_domain == od or raw_domain.endswith('.' + od)
                    for od in official_list
                )
                if not is_official:
                    score += 55
                    reasons.append(
                        f'Brand impersonation: nama "{brand}" ada di domain tidak resmi '
                        f'(domain resmi: {", ".join(official_list[:2])})'
                    )
                    break
    except Exception:
        pass

    return min(100, score), reasons

# ── ML Scorer ─────────────────────────────────────────────────────────────────
def ml_score(url: str):
    if not MODELS_LOADED:
        return 0.0, 0.0
    try:
        f     = extract_features(url)
        vec   = TFIDF.transform([url]).toarray()
        sc    = SCALER.transform(np.array([[f['url_length'], f['num_dots'], f['num_special']]]))
        proba = RF.predict_proba(np.hstack([vec, sc]))[0][1]
        return min(100.0, round(proba * 100, 1)), float(proba)
    except Exception:
        return 0.0, 0.0

# ── Main Predict ──────────────────────────────────────────────────────────────
def predict(url: str) -> dict:
    h_score, reasons = heuristic_score(url)
    m_score, raw_proba = ml_score(url)
    f = extract_features(url)

    if MODELS_LOADED:
        if raw_proba >= 0.60:
            verdict, level = 'PHISHING', 'danger'
        elif raw_proba >= 0.15:
            verdict, level = 'SUSPICIOUS', 'warning'
        else:
            if   h_score >= 55: verdict, level = 'PHISHING',  'danger'
            elif h_score >= 30: verdict, level = 'SUSPICIOUS', 'warning'
            else:               verdict, level = 'SAFE',        'safe'

        strong = (f['has_ip'], f['num_at'] > 0, f['suspicious_tld'])
        strong_count = sum(strong)
        if strong_count >= 2 and verdict == 'SAFE':
            verdict, level = 'PHISHING', 'danger'
        elif strong_count >= 1 and verdict == 'SAFE':
            verdict, level = 'SUSPICIOUS', 'warning'

        if raw_proba >= 0.15:
            final = min(100.0, round(m_score * 0.6 + h_score * 0.4, 1))
        else:
            final = min(100.0, float(h_score))
    else:
        final = min(100.0, float(h_score))
        if   final >= 55: verdict, level = 'PHISHING',  'danger'
        elif final >= 30: verdict, level = 'SUSPICIOUS', 'warning'
        else:             verdict, level = 'SAFE',        'safe'

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
            self._respond(400, {'error': 'URL required'})
            return

        result = predict(url)
        self._respond(200, result)

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
