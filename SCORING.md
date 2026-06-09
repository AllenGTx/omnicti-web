# 🧮 Risk Scoring Documentation

This document provides a comprehensive technical breakdown of the OmniCTI risk assessment engine. OmniCTI employs a **Hybrid Scoring Model** that prioritizes **AI-Refined Analysis** but maintains a robust **Deterministic Fallback**.

---

## 🧠 1. AI-Refined Scoring (Primary)

The AI engine takes raw technical findings and contextualizes them using a Large Language Model (LLM) acting as a **Senior Cyber Risk Auditor**.

### 1.1. Aggregation Logic (The "Corroboration" Model)

To prevent a single hallucination or false positive from skewing the risk score to Critical, OmniCTI uses a **Provider-Capped Aggregation** model.

**Formula:**
$$
\text{Final Score} = \min\left(100, \sum_{\text{provider}} \left( \text{AI\_Score}_{\text{provider}} \times 2.0 \right) \right)
$$

**Rules:**
1.  **Per-Provider Isolation**: Findings are grouped by source (e.g., Shodan, LeakIX) and analyzed independently.
2.  **Score Normalization**: The AI returns a score on a `0.0 - 10.0` scale.
3.  **Contribution Cap**: Each provider contributes a maximum of **20 points** (20%) to the final score.
    *   *Example*: If LeakIX reports a Critical issue (AI Score 10.0), it adds exactly 20 points.
4.  **Corroboration Requirement**: To reach a **Critical (100)** score, you need high-severity confirmations from at least **5 distinct sources**.

### 1.2. AI Persona & Criteria

The LLM is prompted with the following persona and strict scoring criteria:

**Role**: Senior Cyber Risk Auditor.
**Philosophy**: Avoid "Severity Inflation". A vulnerability is only Critical if it is reachable, exploitable, and impacts business continuity.

**Scoring Scale:**
| Score | Risk Level | Criteria |
| :--- | :--- | :--- |
| **9.0 - 10.0** | **CRITICAL** | Active Breach, Cleartext Credentials (DB_PASSWORD), PII Leakage, RCE in CISA KEV. |
| **7.0 - 8.9** | **HIGH** | Unprotected Admin Panels (wp-admin), Sensitive File Exposure (.env, .git), High EPSS CVEs. |
| **4.0 - 6.9** | **MEDIUM** | Information Disclosure (phpinfo), Directory Listings, Outdated Software (No Exploit). |
| **0.1 - 3.9** | **LOW** | Standard Service Exposure (80/443), Version Disclosure, Weak Ciphers. |

---

## ⚙️ 2. Deterministic Scoring (Fallback)

If the AI service is unavailable, OmniCTI falls back to a purely mathematical model. This model has been tuned to mimic the AI's "Provider-Capped" logic to ensure consistency.

### 2.1. Individual Finding Score
Every single finding acts as a data point with a calculated risk score:

$$
\text{Score} = \text{Base} \times \text{Multiplier} \times \text{Reliability} \times \text{Decay}
$$

### 2.2. Component Breakdown

#### A. Base Severity (`Base`)
Derived from the finding's intrinsic severity (CVSS or provider mapping).
*   **Critical**: 100.0
*   **High**: 75.0
*   **Medium**: 50.0
*   **Low**: 25.0
*   **Info**: 10.0

#### B. Business Logic Multiplier (`Multiplier`)
Context-aware boosting based on keywords in the finding's title, product, or summary.
*   **Secrets/Keys** (`.env`, `id_rsa`, `config.php`): **2.0x**
*   **Admin Panels** (`wp-admin`, `dashboard`, `cpanel`): **1.5x**
*   **Dev Artifacts** (`.git`, `swagger.json`): **1.2x**
*   **Default**: **1.0x**

#### C. Source Reliability (`Reliability`)
Weights sources based on their verification method (Active verification > Passive collection).
*   **LeakIX**: 1.0 (High Trust - Verified Evidence)
*   **AlienVault**: 0.9 (High Trust - Threat Intel)
*   **IPInfo**: 0.8 (High Trust - Infrastructure)
*   **Shodan**: 0.7 (Medium Trust - Active Scan)
*   **Censys**: 0.6 (Medium Trust - Active Scan)
*   **VirusTotal**: 0.5 (Variable Trust - Aggregator)

#### D. Temporal Decay (`Decay`)
Reduces noise from old/stale data using an exponential decay formula.

$$
\text{Decay} = e^{-\lambda \times \text{days\_since\_seen}}
$$

*   **Lambda ($\lambda$)**: `0.023` (Half-life $\approx$ 30 days).

| Age of Finding | Decay Factor | Effect |
| :--- | :--- | :--- |
| **0 Days (Today)** | **1.00** | Full Score |
| **7 Days** | **0.85** | Slight Reduction |
| **30 Days** | **0.50** | Half Score |
| **60 Days** | **0.25** | Quarter Score |
| **90+ Days** | **< 0.12** | Negligible |

### 2.3. Deterministic Aggregation
To align with the AI model, the deterministic engine sums individual finding scores using the same logic:

1.  **Sum by Provider**: Calculate total score for all findings from Source X.
2.  **Cap by Provider**: $\min(20.0, \text{Sum}_{\text{Source X}})$.
3.  **Sum Total**: $\min(100.0, \sum \text{Capped\_Provider\_Scores})$.

---

## 📝 3. Example Calculation

**Scenario:** A domain `example.com` has two findings.

### Finding 1: Exposed `.env` file (found by LeakIX today)
*   **Base**: Critical (100.0)
*   **Multiplier**: "Secrets" keyword match (2.0x)
*   **Reliability**: LeakIX (1.0)
*   **Decay**: 0 days old (1.0)
*   **Math**: $100 \times 2.0 \times 1.0 \times 1.0 = 200.0$
*   **Provider Cap**: LeakIX contributes **20.0** (Capped).

### Finding 2: Old CVE-2019-1234 (found by Shodan 60 days ago)
*   **Base**: High (75.0)
*   **Multiplier**: Default (1.0x)
*   **Reliability**: Shodan (0.7)
*   **Decay**: 60 days old ($e^{-0.023 \times 60} \approx 0.25$)
*   **Math**: $75 \times 1.0 \times 0.7 \times 0.25 \approx 13.1$
*   **Provider Cap**: Shodan contributes **13.1** (Below Cap).

### Final Score
$$
\text{Total} = 20.0 (\text{LeakIX}) + 13.1 (\text{Shodan}) = \mathbf{33.1} \text{ (Medium Risk)}
$$

*Note how the critical `.env` file would score 200 in a raw system, but here it is capped at 20. This forces the system to look for corroboration from other sources to escalate the risk further.*

---

## 🔧 4. Configuration

All weights and multipliers are customizable via `internal/config/scoring.yaml`.

```yaml
severity:
  critical: 100
  high: 75
  medium: 50
  low: 25

reliability:
  sources:
    leakix: 1.0
    shodan: 0.7
    # ... others

business_logic:
  rules:
    - name: "Exposed Secrets"
      keywords: [".env", "id_rsa"]
```

---

## 📚 5. Theoretical Foundations Summary

OmniCTI scoring is grounded in:

*   **NIST SP 800-30 (Risk Assessment)**
*   **ISO/IEC 27005 (Risk Management)**
*   **FAIR quantitative risk modeling**
*   **CVSS specification (FIRST)**
*   **Attack Graph Theory (Roy et al., 2010)**
*   **Exploit Lifecycle Studies (Frei et al., 2009)**
*   **Ensemble Aggregation (Dietterich, 2000)**

### References (Suggested Citations)

1.  **Mell, P., Scarfone, K., & Romanosky, S.** (2019). *CVSS v3.1 Specification*. FIRST.
2.  **NIST SP 800-30 Rev.1** (2012). *Guide for Conducting Risk Assessments*.
3.  **ISO/IEC 27005:2018**. *Information Security Risk Management*.
4.  **Frei, S., May, M., Fiedler, U., & Plattner, B.** (2009). *Large-scale Vulnerability Analysis*. RAID.
5.  **Allodi, L., & Massacci, F.** (2017). *Security Events and Vulnerability Data for Risk Estimation*. WWW.
6.  **Roy, A., Kim, D., & Trivedi, K.** (2010). *Attack Graph Based Risk Assessment*. IEEE.
7.  **Schneier, B.** (1999). *Attack Trees*. Dr. Dobb’s Journal.
8.  **Dietterich, T.** (2000). *Ensemble Methods in Machine Learning*.
9.  **Rescorla, E.** (2005). *Is Finding Security Holes a Good Idea?* IEEE Security & Privacy.
