---
name: Phishing ML distribution shift
description: The bundled RandomForest model gives near-constant ~5-6% probability for most real-world URLs, indicating it was trained on a narrow dataset. Heuristic is more reliable for general use.
---

## Rule
Do NOT use raw ML probability as the sole primary classifier. The RF model outputs ~5-6% for almost every real-world URL (both phishing and legitimate), making it non-discriminating outside its training distribution.

**Why:** The TFIDF vocabulary contains tokens like `000webhostapp`, `007xenstry`, `069aa8d1` — specific URL fragments from a narrow training dataset (possibly one Kaggle/PhishTank snapshot). The model memorized patterns from that exact distribution. Real-world URLs fall outside this distribution.

**How to apply:**
- ML is trusted only when raw_proba >= 0.60 (clear hit on training distribution)
- ML moderately informative at 0.15–0.60
- Below 0.15: treat as "uncertain" → fall back to heuristic
- Heuristic is the primary classifier for out-of-distribution URLs
- Heuristic PHISHING threshold: 55, SUSPICIOUS threshold: 30
- Safety upgrade: if ML uncertain AND (has_ip OR num_at>0 OR suspicious_tld) → upgrade SAFE to at least SUSPICIOUS
- If 2+ strong signals AND ML uncertain → upgrade directly to PHISHING
