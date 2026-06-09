# OmniCTI (OmniCTI)

<div align="center">

# 🛡️ OmniCTI

<p>
    <a href="https://golang.org/doc/install"><img src="https://img.shields.io/badge/go-1.23%2B-blue.svg" alt="Go Version"></a>
    <img src="https://img.shields.io/badge/AI-Powered-purple.svg" alt="AI Powered">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>
<p>
    <img src="https://img.shields.io/badge/Linux-Supported-green.svg" alt="Linux Supported">
    <img src="https://img.shields.io/badge/macOS-Supported-green.svg" alt="macOS Supported">
    <img src="https://img.shields.io/badge/Windows-Supported-green.svg" alt="Windows Supported">
</p>

</div>

## 🏗️ Architecture

OmniCTI is built as a modular Golang application following **Clean Architecture** principles.

### Core Components
- **Engine (`internal/core`)**: Orchestrates the scanning lifecycle.
- **Sources (`internal/ctisource`)**: Adapters for external APIs (Strategy Pattern).
- **Normalization (`internal/normalize`)**: Converts raw JSON/XML from sources into uniform `Finding` structs.
- **Scoring (`internal/scoring`)**: Pure logic functions for calculating risk.
- **AI (`internal/ai`)**: Client interface for LLM providers (Gemini/OpenAI/Groq).
- **Aggregation (`internal/aggregation`)**: Combines scored findings into a final `Result`.

### Directory Structure
```
domainscorer/
├── cmd/
│   ├── domain-intel/       # Main entry point (CLI & Server)
│   └── experiment/         # Bulk analysis & validation tool
├── internal/
│   ├── aggregation/        # Result compiling & Score capping
│   ├── ai/                 # LLM Client & Prompts
│   ├── config/             # YAML loader via Viper
│   ├── core/               # Main execution loop
│   ├── ctisource/          # Source implementations (LeakIX, Shodan, etc.)
│   ├── normalize/          # Data standardization
│   ├── report/             # HTML/JSON generation
│   ├── scoring/            # Math & Business Logic
│   └── server/             # HTTP Handlers
└── README.md
```

---

## 🚀 Key Features

### 1. Multi-Source Intelligence Aggregation
OmniCTI queries 9+ top-tier CTI providers concurrently to build a 360-degree view of the target domain.
- **Surface**: Shodan, Censys, ZoomEye (Ports, Banners, Services)
- **Vulnerability**: LeakIX, AlienVault OTX (CVEs, Misconfigurations)
- **Reputation**: VirusTotal, AbuseIPDB, ThreatBook (Malware, Blacklists)
- **Infrastructure**: IPInfo (Geolocation, ASN)

### 2. AI-Powered Risk Analysis (Per-Provider)
Unlike traditional scanners that dump raw data, OmniCTI uses GenAI to act as a **Senior Cyber Risk Auditor**.
- **Contextual Analysis**: It doesn't just read banners; it understands *implications* (e.g., "Exposed port 21 is bad" vs "Exposed port 21 on a Bank server is Critical").
- **Weighted Aggregation**:
  - Findings are grouped by provider.
  - Each provider is analyzed independently to prevent hallucination overlapping.
  - **Logic**: `FinalScore = Min(100, Sum(Provider_Score * 2.0))`
  - **Cap**: Each provider contributes max 20 points. Critical risk requires corroboration from 5+ sources or max-severity findings from massive exposure.

### 3. Temporal Risk Decay
Vulnerabilities get stale. A CVE from 2020 is less risky than a CVE from today *if* the asset hasn't been seen recently.
- **Formula**: `Decay = e^(-λ * days_since_seen)`
- **Lambda (λ)**: `0.023` (Half-life of ~30 days).
- **Effect**: A critical finding last seen 6 months ago will have a drastically reduced score compared to one seen today.

### 4. Context-Aware Business Logic
OmniCTI applies heuristic rules to boost scores for high-value targets.
- **Exposed Secrets**: `.env`, `id_rsa`, `config.php` → **2.0x Multiplier**
- **Admin Interfaces**: `wp-admin`, `dashboard`, `cpanel` → **1.5x Multiplier**
- **Development Artifacts**: `.git`, `swagger.json` → **1.2x Multiplier**

---

## 📋 Table of Contents

- [✨ Features](#-key-features)
- [🧮 Risk Scoring](#-risk-scoring-engine)
- [🔩 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [🔬 Research & Validation](#-research--validation)
- [🔧 Advanced Configuration](#-advanced-configuration)
- [💻 Command-Line Options](#-command-line-options)
- [📊 JSON Report Structure](#-json-report-structure)

---

## 🧮 Risk Scoring Engine

For detailed information on the scoring algorithms, AI aggregation logic, and validation methodology, please see **[scoring.md](scoring.md)**.

### Summary
OmniCTI uses a **Provider-Capped Aggregation** model (max 20 points per source) to prevent single-source saturation, ensuring that Critical scores require corroboration. This logic is applied both in the AI analysis and the deterministic fallback.


---

## 🔩 Installation

### Prerequisites

- **Go (Golang)** 1.23 or newer.

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/sekawansec/cti4u
    cd cti4u
    ```

2.  **Build the Binary:**
    ```bash
    go build -o domain-intel ./cmd/domain-intel/main.go
    ```

3.  **Set up Environment:**
    Create a `.env` file in the root directory for your API keys:
    ```env
    SHODAN_KEY=your_shodan_key
    CENSYS_API_ID=your_censys_id
    CENSYS_API_SECRET=your_censys_secret
    VIRUSTOTAL_KEY=your_vt_key
    GEMINI_API_KEY=your_gemini_key # Optional: For AI Analysis
    ```

---

## 🚀 Quick Start

### Basic Scan
Run a standard scan against a target domain.
```bash
./domain-intel example.com
```

### Web Server Mode
Start the interactive web interface.
```bash
./domain-intel -http :8080
```
Open [http://localhost:8080](http://localhost:8080) in your browser.

### Enable AI Analysis & JSON Output
Generate a detailed JSON report including AI-driven insights.
```bash
./domain-intel -json -v example.com > result.json
```

---

## 🔬 Research & Validation

For methodology and validation experiments, please see **[scoring.md](scoring.md#research--validation)**.

---

## 🔧 Advanced Configuration

OmniCTI uses a simplified YAML configuration. You can override defaults by creating a `internal/config/scoring.yaml` file (or pointing to one with `-config`).

### Ref. `internal/config/scoring.yaml`

```yaml
# Severity Impacts (Base Score)
severity:
  critical: 100   # CVSS 9.0-10.0
  high: 75        # CVSS 7.0-8.9
  medium: 50      # CVSS 4.0-6.9
  low: 25         # CVSS 0.1-3.9
  info: 10        # Information only

# CTI Source Reliability Weights (0.0 - 1.0)
reliability:
  sources:
    leakix: 1.0       # Verified Evidence (High Trust)
    alienvault: 0.9   # Threat Intel (High Trust)
    shodan: 0.7       # Active Scan (Medium Trust)
    censys: 0.6       # Active Scan (Medium Trust)
    virustotal: 0.5   # Aggregator (Variable Trust)
    ipinfo: 0.8       # Infrastructure (High Trust)
  default: 0.5        # Fallback for unknown sources

# Business Logic Rules (Context Awareness)
business_logic:
  rules:
    - name: "Exposed Secrets"
      keywords: [".env", "id_rsa", "aws_key", "config.php"]
      multiplier: 2.0  # Double the risk score
    
    - name: "Admin Panels"
      keywords: ["wp-admin", "dashboard", "cpanel", "administration"]
      multiplier: 1.5  # +50% risk score

# AI Analysis Configuration
ai:
  enabled: true
  provider: "gemini" # Options: "gemini", "openai", "groq"
  model: "gemini-1.5-flash"
  max_tokens: 2048
```

---

## 💻 Command-Line Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-json` | Output results in machine-readable JSON format. | `false` |
| `-report` | Path to save the interactive HTML report (e.g., `report.html`). | `""` |
| `-http` | Start the web server on the specified address (e.g., `:8080`). | `""` |
| `-config` | Path to the YAML scoring configuration file. | `internal/config/scoring.yaml` |
| `-v` | Enable verbose/debug output (useful for troubleshooting API errors). | `false` |

---

## 📊 JSON Report Structure

The JSON output is designed for integration with SIEMs and pipelines.

```json
{
  "domain": "example.com",
  "score": 85.5,
  "level": "Critical",
  "findings": [
    {
      "Source": "alienvault",
      "Type": "vulnerability",
      "Severity": "high",
      "Asset": "1.2.3.4"
    }
  ],
  "ai_analysis": {
    "risk_level": "HIGH",
    "final_score": 75.0,
    "providers": [
      {
        "provider": "shodan",
        "contribution": 18.5,
        "analysis": {
             "analysis_summary": "Critical CVE found...",
             "findings_analysis": [...]
        }
      }
    ]
  }
}
```

---

## 📝 Configuration

Customize risk weights in `internal/config/scoring.yaml`:

```yaml
severity:
  critical: 100
  high: 75

business_logic:
  rules:
    - name: "Exposed Secrets"
      keywords: [".env", "config.php"]
      multiplier: 2.0
```

---

## 🛠️ Troubleshooting

### Common Issues

**1. "Analysis failed: AI Init Failed"**
- **Cause**: Missing or invalid API Key.
- **Fix**: Check your `.env` file. Ensure `GEMINI_API_KEY` (or relevant key) is set.
- **Debug**: Run with `-v` to see the exact error from the provider.

**2. "Zero Findings" for a known bad domain**
- **Cause**: API Quotas or Network Filtering.
- **Fix**:
    - Verify your Shodan/Censys/VirusTotal API quotas.
    - Check if your IP is blocked by the target.
    - Run with `-v` to see individual source errors (e.g., `[!] Shodan: 403 Forbidden`).

**3. "Score remains at 100"**
- **Cause**: Saturation.
- **Fix**: Identify the critical finding driving the score. If it's a false positive (e.g., a honeypot), adjust the `Business Logic` keywords to exclude it or whitelist the asset in code (future feature).

---

## 🧑‍💻 Development Guide

OmniCTI is designed to be easily extensible.

### Adding a New CTI Source
1.  **Create Package**: Add `internal/ctisource/newsource/`.
2.  **Implement Interface**: Implement the `base.Source` interface:
    ```go
    type Source interface {
        Name() string
        Fetch(ctx context.Context, domain string) ([]normalize.Finding, error)
    }
    ```
3.  **Register**: Add your new source to `cmd/domain-intel/main.go` inside the `sources` slice.
4.  **Configure**: Add reliability weights in `scoring.yaml`.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a PR.

## 📄 License

[MIT License](LICENSE)
