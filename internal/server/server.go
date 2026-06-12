package server

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "os"
        "strings"
        "time"

        "domainscorer/internal/aggregation"
        "domainscorer/internal/ai"
        "domainscorer/internal/config"
        "domainscorer/internal/core"
        "domainscorer/internal/ctisource/abuseipdb"
        "domainscorer/internal/ctisource/alienvault"
        "domainscorer/internal/ctisource/base"
        "domainscorer/internal/ctisource/censys"
        "domainscorer/internal/ctisource/ipinfo"
        "domainscorer/internal/ctisource/leakix"
        "domainscorer/internal/ctisource/shodan"
        "domainscorer/internal/ctisource/threatbook"
        "domainscorer/internal/ctisource/virustotal"
        "domainscorer/internal/ctisource/zoomeye"
        "domainscorer/internal/normalize"
        "domainscorer/internal/report"
        "domainscorer/internal/scoring"

        openai "github.com/sashabaranov/go-openai"
)

var phishingHTTPClient = &http.Client{Timeout: 30 * time.Second}

// Start initializes and runs the HTTP server on the specified address.
func Start(addr string) error {
        http.HandleFunc("/", handleIndex)
        http.HandleFunc("/scan", handleScan)
        http.HandleFunc("/phishing", handlePhishing)
        http.HandleFunc("/api/phishing/predict", handlePhishingPredict)
        http.HandleFunc("/api/phishing/analyze", handlePhishingAnalyze)

        fmt.Printf("[*] Web Server listening on %s\n", addr)
        return http.ListenAndServe(addr, nil)
}

// handlePhishingPredict proxies POST /api/phishing/predict → Python service :5001/predict
func handlePhishingPredict(w http.ResponseWriter, r *http.Request) {
        proxyToPhishingService(w, r, "http://localhost:5001/predict")
}

// handlePhishingAnalyze calls Groq LLM directly from Go (bypasses Python for Cloudflare compat).
func handlePhishingAnalyze(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(r.Body)
        if err != nil {
                phishingWriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Failed to read request"})
                return
        }
        defer r.Body.Close()

        var reqData struct {
                URL    string                 `json:"url"`
                Result map[string]interface{} `json:"result"`
        }
        if err := json.Unmarshal(body, &reqData); err != nil || reqData.URL == "" {
                phishingWriteJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "url is required"})
                return
        }

        scanResult := reqData.Result
        if len(scanResult) == 0 {
                predictBody, _ := json.Marshal(map[string]string{"url": reqData.URL})
                predictReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
                        "http://localhost:5001/predict", bytes.NewReader(predictBody))
                predictReq.Header.Set("Content-Type", "application/json")
                if predictResp, perr := phishingHTTPClient.Do(predictReq); perr == nil {
                        defer predictResp.Body.Close()
                        predictData, _ := io.ReadAll(predictResp.Body)
                        json.Unmarshal(predictData, &scanResult) //nolint:errcheck
                }
        }

        apiKey := os.Getenv("GROQ_API_KEY")
        if apiKey == "" {
                phishingWriteJSON(w, http.StatusOK, map[string]interface{}{
                        "ai_analysis": map[string]string{"error": "GROQ_API_KEY tidak ditemukan"},
                        "url":         reqData.URL,
                })
                return
        }

        verdict := phishingMapStr(scanResult, "verdict", "UNKNOWN")
        score := phishingMapFloat(scanResult, "score", 0)
        mlScore := phishingMapFloat(scanResult, "ml_score", 0)
        hScore := phishingMapFloat(scanResult, "heuristic_score", 0)

        var reasonLines []string
        if rv, ok := scanResult["reasons"]; ok {
                if rs, ok := rv.([]interface{}); ok {
                        for _, item := range rs {
                                if s, ok := item.(string); ok {
                                        reasonLines = append(reasonLines, "- "+s)
                                }
                        }
                }
        }
        reasonsText := strings.Join(reasonLines, "\n")
        if reasonsText == "" {
                reasonsText = "- Tidak ada indikator mencurigakan"
        }

        var features map[string]interface{}
        if fv, ok := scanResult["features"]; ok {
                if fm, ok := fv.(map[string]interface{}); ok {
                        features = fm
                }
        }
        if features == nil {
                features = map[string]interface{}{}
        }

        prompt := fmt.Sprintf(`Kamu adalah seorang ahli keamanan siber senior yang menganalisis URL untuk mendeteksi phishing.

URL yang dianalisis: %s

Hasil deteksi otomatis:
- Verdict: %s
- Risk Score: %.1f/100
- ML Score: %.1f/100
- Heuristic Score: %.1f/100

Indikator yang ditemukan:
%s

Detail fitur URL:
- Panjang URL: %d karakter
- Menggunakan HTTPS: %v
- Ada IP address: %v
- TLD mencurigakan: %v
- Kata kunci phishing: %d ditemukan

Berikan analisis HANYA dalam format JSON murni (tanpa markdown, tanpa komentar, langsung mulai dari tanda kurung kurawal):
{
  "ringkasan": "Penjelasan singkat 1-2 kalimat tentang URL ini",
  "analisis_detail": "Analisis mendalam 3-5 kalimat menjelaskan mengapa URL ini berbahaya/aman, teknik phishing yang digunakan jika ada, dan konteks ancamannya",
  "target_korban": "Siapa yang menjadi target serangan ini dan mengapa",
  "tingkat_bahaya": "Penjelasan tingkat bahaya dalam 1-2 kalimat",
  "saran_tindakan": ["Saran tindakan 1", "Saran tindakan 2", "Saran tindakan 3", "Saran tindakan 4"],
  "tanda_peringatan": ["Tanda peringatan utama 1", "Tanda peringatan utama 2", "Tanda peringatan utama 3"],
  "kesimpulan": "Kesimpulan akhir dan rekomendasi utama dalam 1-2 kalimat"
}`,
                reqData.URL, verdict, score, mlScore, hScore, reasonsText,
                int(phishingMapFloat(features, "url_length", 0)),
                phishingMapBool(features, "is_https"),
                phishingMapBool(features, "has_ip"),
                phishingMapBool(features, "suspicious_tld"),
                int(phishingMapFloat(features, "phishing_keywords", 0)),
        )

        oaiCfg := openai.DefaultConfig(apiKey)
        oaiCfg.BaseURL = "https://api.groq.com/openai/v1"
        groqClient := openai.NewClientWithConfig(oaiCfg)

        ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
        defer cancel()

        groqResp, err := groqClient.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
                Model: "llama-3.3-70b-versatile",
                Messages: []openai.ChatCompletionMessage{
                        {Role: openai.ChatMessageRoleUser, Content: prompt},
                },
                Temperature: 0.3,
                MaxTokens:   1500,
        })
        if err != nil {
                phishingWriteJSON(w, http.StatusOK, map[string]interface{}{
                        "ai_analysis": map[string]string{"error": "Groq API error: " + err.Error()},
                        "url":         reqData.URL,
                })
                return
        }
        if len(groqResp.Choices) == 0 {
                phishingWriteJSON(w, http.StatusOK, map[string]interface{}{
                        "ai_analysis": map[string]string{"error": "Empty response from Groq"},
                        "url":         reqData.URL,
                })
                return
        }

        text := strings.TrimSpace(groqResp.Choices[0].Message.Content)
        text = strings.TrimPrefix(text, "```json")
        text = strings.TrimPrefix(text, "```")
        text = strings.TrimSuffix(text, "```")
        text = strings.TrimSpace(text)

        var aiResult map[string]interface{}
        if err := json.Unmarshal([]byte(text), &aiResult); err != nil {
                phishingWriteJSON(w, http.StatusOK, map[string]interface{}{
                        "ai_analysis": map[string]string{"error": "Gagal parse respons AI: " + err.Error()},
                        "url":         reqData.URL,
                })
                return
        }

        phishingWriteJSON(w, http.StatusOK, map[string]interface{}{
                "ai_analysis": aiResult,
                "url":         reqData.URL,
        })
}

func phishingWriteJSON(w http.ResponseWriter, status int, data interface{}) {
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(data) //nolint:errcheck
}

func phishingMapStr(m map[string]interface{}, key, def string) string {
        if v, ok := m[key]; ok {
                if s, ok := v.(string); ok {
                        return s
                }
        }
        return def
}

func phishingMapFloat(m map[string]interface{}, key string, def float64) float64 {
        if v, ok := m[key]; ok {
                switch n := v.(type) {
                case float64:
                        return n
                case int:
                        return float64(n)
                }
        }
        return def
}

func phishingMapBool(m map[string]interface{}, key string) bool {
        if v, ok := m[key]; ok {
                if b, ok := v.(bool); ok {
                        return b
                }
        }
        return false
}

func proxyToPhishingService(w http.ResponseWriter, r *http.Request, targetURL string) {
        body, err := io.ReadAll(r.Body)
        if err != nil {
                http.Error(w, "Failed to read request body", http.StatusBadRequest)
                return
        }
        defer r.Body.Close()

        req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
        if err != nil {
                http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
                return
        }
        req.Header.Set("Content-Type", "application/json")

        resp, err := phishingHTTPClient.Do(req)
        if err != nil {
                http.Error(w, `{"error":"Phishing service tidak tersedia. Pastikan phishing_service.py berjalan."}`, http.StatusServiceUnavailable)
                return
        }
        defer resp.Body.Close()

        respBody, _ := io.ReadAll(resp.Body)
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.WriteHeader(resp.StatusCode)
        w.Write(respBody)
}

func handlePhishing(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.Write([]byte(phishingPageHTML))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
                http.NotFound(w, r)
                return
        }
        w.Header().Set("Content-Type", "text/html")
        w.Write([]byte(landingPageHTML))
}

// handleScan processes the domain scan request.
// It orchestrates the discovery, CTI fetching, normalization, scoring, and AI analysis.
// Finally, it renders the results using the HTML report structure.
func handleScan(w http.ResponseWriter, r *http.Request) {
        domain := r.FormValue("domain")
        if domain == "" {
                http.Error(w, "Domain is required", http.StatusBadRequest)
                return
        }

        // Initialize sources (duplicated from main.go for now)
        // ideally this should be shared, but keeping it simple for this task.
        sources := []base.Source{
                leakix.NewSource(),
                shodan.NewSource(),
                censys.NewSource(),
                virustotal.NewSource(),
                alienvault.NewSource(),
                zoomeye.NewSource(),
                abuseipdb.NewSource(),
                threatbook.NewSource(),
                ipinfo.NewSource(),
        }

        ctx := context.Background()

        // Run Analysis
        // We might want to stream logs to the user, but for now we'll just wait.
        findings, err := core.Run(ctx, domain, sources)
        if err != nil {
                http.Error(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
                return
        }

        findings = normalize.Dedup(findings)
        score := scoring.Aggregate(findings)

        // AI Analysis using Per-Provider Aggregation
        // Strategy: Group findings by source, analyze each group separately, and aggregate scores.
        var aggregatedAnalysis *ai.AggregatedAnalysis

        aiCfg := &config.CurrentScoringConfig.AI
        if aiCfg.Enabled {
                aggregatedAnalysis = &ai.AggregatedAnalysis{
                        Providers:  []ai.ProviderAnalysis{},
                        Timestamp:  time.Now().Format(time.RFC3339),
                        RiskLevel:  "Unknown",
                        FinalScore: 0.0,
                }

                // Ensure API keys are loaded
                switch aiCfg.Provider {
                case "gemini":
                        aiCfg.APIKey = os.Getenv("GEMINI_API_KEY")
                case "openai":
                        aiCfg.APIKey = os.Getenv("OPENAI_API_KEY")
                case "groq":
                        aiCfg.APIKey = os.Getenv("GROQ_API_KEY")
                }

                aiClient, err := ai.NewAIClient(aiCfg)
                if err == nil {
                        // 1. Group findings by source (e.g., "shodan", "leakix")
                        findingsBySource := make(map[string][]normalize.Finding)
                        for _, f := range findings {
                                findingsBySource[f.Source] = append(findingsBySource[f.Source], f)
                        }

                        // 2. Analyze per source and calculate weighted contribution
                        // Rule: Each provider can contribute at most 20% (20 points) to the final score.
                        totalContribution := 0.0

                        for source, sourceFindings := range findingsBySource {
                                pAnalysis := ai.ProviderAnalysis{
                                        Provider: source,
                                }

                                analysis, err := aiClient.AnalyzeFindings(ctx, domain, sourceFindings)
                                if err != nil {
                                        pAnalysis.Error = err.Error()
                                } else {
                                        pAnalysis.Analysis = analysis
                                        // Calculate Contribution:
                                        // AI returns score 0.0 - 10.0.
                                        // We map this to 0 - 20 points (20% of 100).
                                        // Formula: Score * 2.0
                                        contrib := analysis.AggregatedRiskScore * 2.0
                                        pAnalysis.Contribution = contrib
                                        totalContribution += contrib
                                }
                                aggregatedAnalysis.Providers = append(aggregatedAnalysis.Providers, pAnalysis)
                        }

                        // 3. Final Score Calculation (Capped at 100)
                        if totalContribution > 100.0 {
                                totalContribution = 100.0
                        }
                        aggregatedAnalysis.FinalScore = totalContribution
                        aggregatedAnalysis.RiskLevel = aggregation.InterpretLevel(totalContribution)

                        // 4. Generate Global Executive Summary
                        if len(aggregatedAnalysis.Providers) > 0 {
                                fmt.Printf("   > Generating Global Executive Summary for %s...\n", domain)
                                globalSummary, err := aiClient.GenerateGlobalSummary(ctx, domain, aggregatedAnalysis.Providers)
                                if err != nil {
                                        fmt.Printf("     [!] Failed to generate global summary: %v\n", err)
                                } else {
                                        aggregatedAnalysis.GlobalSummary = globalSummary.GlobalSummary
                                        aggregatedAnalysis.GlobalImpact = globalSummary.GlobalImpact
                                        aggregatedAnalysis.GlobalRemediation = globalSummary.GlobalRemediation
                                }
                        }

                } else {
                        // Global init error, logging to stderr for operator visibility
                        fmt.Fprintf(os.Stderr, "Failed to init AI client: %v\n", err)
                }
        }

        result := aggregation.Build(domain, score, findings)
        result.AIAnalysis = aggregatedAnalysis
        // Note: We do NOT overwrite result.Score with AI score anymore.

        // Render Report
        w.Header().Set("Content-Type", "text/html")
        if err := report.Render(result, w); err != nil {
                http.Error(w, fmt.Sprintf("Failed to render report: %v", err), http.StatusInternalServerError)
        }
}

// landingPageHTML is the new homepage with 2 menu options
const landingPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniCTI - Security Suite</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #e2e8f0; }
        .card-hover { transition: all 0.3s ease; }
        .card-hover:hover { transform: translateY(-4px); box-shadow: 0 20px 40px rgba(0,0,0,0.4); }
        .spinner { border: 4px solid rgba(255,255,255,0.1); width: 36px; height: 36px; border-radius: 50%; border-left-color: #6366f1; animation: spin 1s ease infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center relative overflow-hidden">
    <!-- Background Effects -->
    <div class="absolute top-0 left-0 w-full h-full overflow-hidden -z-10">
        <div class="absolute w-[600px] h-[600px] bg-purple-600/20 rounded-full blur-[120px] -top-32 -left-32"></div>
        <div class="absolute w-[600px] h-[600px] bg-indigo-600/20 rounded-full blur-[120px] bottom-0 right-0"></div>
        <div class="absolute w-[300px] h-[300px] bg-cyan-600/10 rounded-full blur-[80px] top-1/2 left-1/2"></div>
    </div>

    <div class="w-full max-w-2xl px-6 py-12">
        <!-- Header -->
        <div class="text-center mb-12">
            <div class="flex items-center justify-center space-x-3 mb-4">
                <svg class="w-10 h-10 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <h1 class="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">OmniCTI</h1>
            </div>
            <p class="text-slate-400 text-base">Cyber Threat Intelligence & Security Analysis Suite</p>
        </div>

        <!-- Menu Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">

            <!-- Card 1: Domain Security Checker -->
            <div class="card-hover bg-slate-800/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-7 cursor-pointer" onclick="showDomainForm()">
                <div class="flex items-center space-x-4 mb-5">
                    <div class="w-12 h-12 bg-indigo-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                        </svg>
                    </div>
                    <div>
                        <h2 class="text-lg font-semibold text-white">Domain Security Checker</h2>
                        <p class="text-xs text-indigo-400 font-medium mt-0.5">Powered by OmniCTI</p>
                    </div>
                </div>
                <p class="text-slate-400 text-sm leading-relaxed mb-5">Analisis keamanan domain secara menyeluruh menggunakan 9 sumber CTI (Shodan, VirusTotal, Censys, dll) dengan AI Risk Assessment.</p>
                <div class="flex flex-wrap gap-2">
                    <span class="text-xs bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 rounded-full px-3 py-1">9 CTI Sources</span>
                    <span class="text-xs bg-purple-500/10 text-purple-300 border border-purple-500/20 rounded-full px-3 py-1">AI Powered</span>
                    <span class="text-xs bg-slate-700/50 text-slate-300 border border-slate-600/30 rounded-full px-3 py-1">Risk Scoring</span>
                </div>
            </div>

            <!-- Card 2: Phishing Detector -->
            <a href="/phishing" class="card-hover bg-slate-800/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-7 block no-underline">
                <div class="flex items-center space-x-4 mb-5">
                    <div class="w-12 h-12 bg-rose-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                    </div>
                    <div>
                        <h2 class="text-lg font-semibold text-white">Phishing Detector</h2>
                        <p class="text-xs text-rose-400 font-medium mt-0.5">ML-Based Detection</p>
                    </div>
                </div>
                <p class="text-slate-400 text-sm leading-relaxed mb-5">Deteksi URL phishing menggunakan Machine Learning (TF-IDF + Random Forest) dan analisis heuristik berbasis pola ancaman.</p>
                <div class="flex flex-wrap gap-2">
                    <span class="text-xs bg-rose-500/10 text-rose-300 border border-rose-500/20 rounded-full px-3 py-1">ML Detection</span>
                    <span class="text-xs bg-orange-500/10 text-orange-300 border border-orange-500/20 rounded-full px-3 py-1">TF-IDF</span>
                    <span class="text-xs bg-slate-700/50 text-slate-300 border border-slate-600/30 rounded-full px-3 py-1">URL Analysis</span>
                </div>
            </a>
        </div>

        <!-- Domain Scan Form (hidden by default) -->
        <div id="domainFormWrapper" class="hidden mt-8">
            <div class="bg-slate-800/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-7">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-white">Domain Security Checker</h3>
                    <button onclick="hideDomainForm()" class="text-slate-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <form action="/scan" method="POST" id="scanForm" class="space-y-4">
                    <div>
                        <label for="domain" class="block text-sm font-medium text-slate-300 mb-2">Target Domain</label>
                        <div class="relative">
                            <input type="text" name="domain" id="domain" placeholder="example.com" required
                                class="w-full bg-slate-900/50 border border-slate-700 text-white text-base rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent block w-full p-3 pl-10 placeholder-slate-600 transition duration-200">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <svg class="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                            </div>
                        </div>
                    </div>
                    <button type="submit" id="submitBtn"
                        class="w-full flex justify-center py-3 px-4 rounded-lg text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none transition-all duration-200 transform hover:scale-[1.02]">
                        Start Analysis
                    </button>
                </form>
                <div id="loading" class="hidden mt-6 text-center">
                    <div class="flex flex-col items-center space-y-3">
                        <div class="spinner"></div>
                        <p class="text-slate-300 animate-pulse text-sm">Scanning target infrastructure...</p>
                        <p class="text-xs text-slate-500">This may take up to 60 seconds</p>
                    </div>
                </div>
            </div>
        </div>

        <p class="text-center text-slate-600 text-xs mt-8">OmniCTI Security Suite &mdash; For authorized security research only</p>
    </div>

    <script>
        function showDomainForm() {
            document.getElementById('domainFormWrapper').classList.remove('hidden');
            document.getElementById('domainFormWrapper').scrollIntoView({behavior: 'smooth'});
            setTimeout(() => document.getElementById('domain').focus(), 300);
        }
        function hideDomainForm() {
            document.getElementById('domainFormWrapper').classList.add('hidden');
        }
        document.getElementById('scanForm').addEventListener('submit', function() {
            const btn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            btn.disabled = true;
            btn.classList.add('opacity-50', 'cursor-not-allowed');
            loading.classList.remove('hidden');
            document.getElementById('domain').readOnly = true;
        });
    </script>
</body>
</html>
`

// phishingPageHTML is the Phishing Detector page
const phishingPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniCTI - Phishing Detector</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #e2e8f0; }
        .spinner { border: 4px solid rgba(255,255,255,0.1); width: 28px; height: 28px; border-radius: 50%; border-left-color: #f43f5e; animation: spin 1s ease infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .score-bar { transition: width 1s ease-in-out; }
        .pulse-danger { animation: pulseDanger 2s infinite; }
        @keyframes pulseDanger { 0%,100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.4); } 50% { box-shadow: 0 0 0 10px rgba(239,68,68,0); } }
        .pulse-warning { animation: pulseWarning 2s infinite; }
        @keyframes pulseWarning { 0%,100% { box-shadow: 0 0 0 0 rgba(234,179,8,0.4); } 50% { box-shadow: 0 0 0 10px rgba(234,179,8,0); } }
    </style>
</head>
<body class="min-h-screen relative">
    <!-- Background -->
    <div class="fixed top-0 left-0 w-full h-full -z-10">
        <div class="absolute w-[500px] h-[500px] bg-rose-600/15 rounded-full blur-[100px] -top-20 -right-20"></div>
        <div class="absolute w-[500px] h-[500px] bg-purple-600/15 rounded-full blur-[100px] bottom-0 left-0"></div>
    </div>

    <!-- Header -->
    <header class="bg-slate-900/80 border-b border-slate-800 sticky top-0 z-50 backdrop-blur-md">
        <div class="max-w-4xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <!-- Back Button -->
                <a href="/" class="flex items-center space-x-2 text-slate-400 hover:text-white transition-colors mr-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                    </svg>
                    <span class="text-sm font-medium">Back</span>
                </a>
                <div class="w-px h-6 bg-slate-700"></div>
                <svg class="w-7 h-7 text-rose-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <h1 class="text-lg font-bold text-white">Phishing Detector</h1>
            </div>
            <span class="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-full px-3 py-1">ML-Based</span>
        </div>
    </header>

    <main class="max-w-4xl mx-auto px-4 py-10">

        <!-- Input Form -->
        <div class="bg-slate-800/60 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-7 mb-8">
            <h2 class="text-base font-semibold text-slate-200 mb-1">Masukkan URL untuk Diperiksa</h2>
            <p class="text-sm text-slate-500 mb-5">Contoh: http://paypal-login.suspicious.com/verify atau https://google.com</p>
            <div class="flex gap-3">
                <div class="relative flex-1">
                    <input type="text" id="urlInput" placeholder="https://example.com/page?id=123"
                        class="w-full bg-slate-900/60 border border-slate-700 text-white rounded-xl focus:ring-2 focus:ring-rose-500 focus:border-transparent p-3 pl-10 placeholder-slate-600 transition duration-200 text-sm">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                        </svg>
                    </div>
                </div>
                <button onclick="checkPhishing()" id="checkBtn"
                    class="px-6 py-3 bg-rose-600 hover:bg-rose-700 text-white font-medium rounded-xl transition-all duration-200 transform hover:scale-[1.02] text-sm whitespace-nowrap">
                    Cek URL
                </button>
            </div>
            <!-- Loading -->
            <div id="loadingState" class="hidden mt-5 flex items-center space-x-3">
                <div class="spinner"></div>
                <span class="text-sm text-slate-400 animate-pulse">Menganalisis URL...</span>
            </div>
        </div>

        <!-- Result -->
        <div id="result" class="hidden">

            <!-- Verdict Banner -->
            <div id="verdictBanner" class="rounded-2xl p-6 mb-6 border">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div id="verdictIcon" class="w-14 h-14 rounded-full flex items-center justify-center text-2xl"></div>
                        <div>
                            <p class="text-sm text-slate-400 mb-1">Hasil Analisis</p>
                            <p id="verdictText" class="text-2xl font-bold"></p>
                            <p id="verdictUrl" class="text-xs text-slate-500 mt-1 font-mono break-all"></p>
                        </div>
                    </div>
                    <div class="text-right">
                        <p class="text-xs text-slate-500 mb-1">Risk Score</p>
                        <p id="scoreText" class="text-4xl font-bold"></p>
                        <p class="text-xs text-slate-500">/100</p>
                    </div>
                </div>

                <!-- Score Bar -->
                <div class="mt-5">
                    <div class="w-full bg-slate-700/50 rounded-full h-2.5">
                        <div id="scoreBar" class="score-bar h-2.5 rounded-full" style="width: 0%"></div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">

                <!-- Reasons -->
                <div class="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-5">
                    <h3 class="text-sm font-semibold text-slate-300 mb-4 flex items-center space-x-2">
                        <svg class="w-4 h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span>Alasan Deteksi</span>
                    </h3>
                    <ul id="reasonsList" class="space-y-2"></ul>
                    <p id="noReasons" class="hidden text-sm text-slate-500 italic">Tidak ada indikator mencurigakan</p>
                </div>

                <!-- Features -->
                <div class="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-5">
                    <h3 class="text-sm font-semibold text-slate-300 mb-4 flex items-center space-x-2">
                        <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                        </svg>
                        <span>Analisis Fitur URL</span>
                    </h3>
                    <div id="featuresList" class="space-y-2"></div>
                </div>
            </div>

            <!-- AI Analysis Section -->
            <div id="aiAnalysisSection" class="mt-5 hidden">
                <div id="aiLoading" class="bg-slate-800/60 border border-purple-500/30 rounded-2xl p-6">
                    <div class="flex items-center space-x-4">
                        <div class="spinner" style="border-left-color:#a855f7;border-width:3px;width:24px;height:24px;"></div>
                        <div>
                            <p class="text-sm font-semibold text-purple-300">Groq AI sedang menganalisis ancaman...</p>
                            <p class="text-xs text-slate-500 mt-0.5">Memproses konteks, pola serangan, dan rekomendasi keamanan</p>
                        </div>
                    </div>
                </div>
                <div id="aiResult" class="hidden"></div>
            </div>

            <!-- Check Another -->
            <div class="mt-6 text-center">
                <button onclick="resetForm()" class="text-sm text-slate-400 hover:text-white transition-colors underline">
                    Cek URL lain
                </button>
            </div>
        </div>

        <!-- Info Box -->
        <div class="mt-8 bg-slate-800/30 border border-slate-700/30 rounded-xl p-5">
            <h3 class="text-sm font-semibold text-slate-400 mb-3">ℹ️ Cara Kerja Phishing Detector</h3>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs text-slate-500">
                <div><span class="text-slate-300 font-medium block mb-1">🤖 TF-IDF Analysis</span>Menganalisis pola teks URL menggunakan model yang dilatih dari ribuan URL phishing</div>
                <div><span class="text-slate-300 font-medium block mb-1">🌲 Random Forest</span>100 decision trees menentukan probabilitas phishing berdasarkan fitur URL</div>
                <div><span class="text-slate-300 font-medium block mb-1">🔍 Heuristic Rules</span>Mengecek indikator mencurigakan: IP di URL, karakter @, TLD berbahaya, keyword phishing</div>
                <div><span class="text-slate-300 font-medium block mb-1">✨ Groq AI</span>Analisis mendalam + saran tindakan dari AI berdasarkan semua temuan</div>
            </div>
        </div>
    </main>

    <script>
        let lastScanResult = null;
        let lastScanUrl = null;

        async function checkPhishing() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) { alert('Masukkan URL terlebih dahulu!'); return; }

            document.getElementById('checkBtn').disabled = true;
            document.getElementById('loadingState').classList.remove('hidden');
            document.getElementById('result').classList.add('hidden');

            try {
                const resp = await fetch('/api/phishing/predict', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                if (!resp.ok) throw new Error('Service tidak tersedia');
                const data = await resp.json();
                lastScanResult = data;
                lastScanUrl = url;
                showResult(data);
                getAiAnalysis(url, data);
            } catch (e) {
                const data = clientSideCheck(url);
                data._fallback = true;
                lastScanResult = data;
                lastScanUrl = url;
                showResult(data);
                getAiAnalysis(url, data);
            } finally {
                document.getElementById('checkBtn').disabled = false;
                document.getElementById('loadingState').classList.add('hidden');
            }
        }

        function clientSideCheck(url) {
            let score = 0; const reasons = [];
            const low = url.toLowerCase();
            if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) { score+=25; reasons.push('IP address digunakan sebagai domain'); }
            if (url.length > 75) { score+=10; reasons.push('URL terlalu panjang ('+url.length+' karakter)'); }
            if ((url.match(/\./g)||[]).length > 4) { score+=10; reasons.push('Banyak titik dalam URL'); }
            if (url.includes('@')) { score+=20; reasons.push('Simbol @ ditemukan di URL'); }
            if (!url.startsWith('https')) { score+=5; reasons.push('Tidak menggunakan HTTPS'); }
            const keywords = ['login','signin','verify','account','secure','paypal','banking','password','confirm'];
            const found = keywords.filter(k => low.includes(k));
            if (found.length) { score+=Math.min(25,found.length*8); reasons.push('Keyword phishing: '+found.join(', ')); }
            const suspTld = ['.tk','.ml','.ga','.cf','.xyz','.top'];
            if (suspTld.some(t => low.includes(t))) { score+=20; reasons.push('TLD mencurigakan'); }
            score = Math.min(100, score);
            const verdict = score>=55?'PHISHING':score>=30?'SUSPICIOUS':'SAFE';
            const level = score>=55?'danger':score>=30?'warning':'safe';
            return {url, score, verdict, level, reasons, features:{url_length:url.length, has_ip:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url), is_https:url.startsWith('https'), phishing_keywords:found.length, num_dots:(url.match(/\./g)||[]).length, suspicious_tld:suspTld.some(t=>low.includes(t)), num_hyphens:(url.match(/-/g)||[]).length, subdomain_count:0}, models_used:false};
        }

        function showResult(data) {
            const banner = document.getElementById('verdictBanner');
            const icon = document.getElementById('verdictIcon');
            const text = document.getElementById('verdictText');
            const urlEl = document.getElementById('verdictUrl');
            const scoreEl = document.getElementById('scoreText');
            const bar = document.getElementById('scoreBar');

            banner.className = 'rounded-2xl p-6 mb-6 border ';
            icon.className = 'w-14 h-14 rounded-full flex items-center justify-center text-2xl ';

            if (data.level === 'danger') {
                banner.className += 'bg-red-500/10 border-red-500/30';
                icon.className += 'bg-red-500/20 pulse-danger';
                icon.innerHTML = '🚨';
                text.className = 'text-2xl font-bold text-red-400';
                text.textContent = '⚠ PHISHING DETECTED';
                scoreEl.className = 'text-4xl font-bold text-red-400';
                bar.className = 'score-bar h-2.5 rounded-full bg-red-500';
            } else if (data.level === 'warning') {
                banner.className += 'bg-yellow-500/10 border-yellow-500/30';
                icon.className += 'bg-yellow-500/20 pulse-warning';
                icon.innerHTML = '⚠️';
                text.className = 'text-2xl font-bold text-yellow-400';
                text.textContent = '⚡ SUSPICIOUS URL';
                scoreEl.className = 'text-4xl font-bold text-yellow-400';
                bar.className = 'score-bar h-2.5 rounded-full bg-yellow-500';
            } else {
                banner.className += 'bg-green-500/10 border-green-500/30';
                icon.className += 'bg-green-500/20';
                icon.innerHTML = '✅';
                text.className = 'text-2xl font-bold text-green-400';
                text.textContent = '✓ URL AMAN';
                scoreEl.className = 'text-4xl font-bold text-green-400';
                bar.className = 'score-bar h-2.5 rounded-full bg-green-500';
            }

            urlEl.textContent = data.url;
            scoreEl.textContent = data.score;
            setTimeout(() => { bar.style.width = data.score + '%'; }, 100);

            // Reasons
            const reasonsList = document.getElementById('reasonsList');
            const noReasons = document.getElementById('noReasons');
            reasonsList.innerHTML = '';
            if (data.reasons && data.reasons.length > 0) {
                noReasons.classList.add('hidden');
                data.reasons.forEach(r => {
                    const li = document.createElement('li');
                    li.className = 'flex items-start space-x-2 text-sm text-slate-300';
                    li.innerHTML = '<span class="text-red-400 mt-0.5">•</span><span>'+r+'</span>';
                    reasonsList.appendChild(li);
                });
            } else {
                noReasons.classList.remove('hidden');
            }

            // Features
            const featuresList = document.getElementById('featuresList');
            featuresList.innerHTML = '';
            const f = data.features;
            const featureItems = [
                {label: 'Panjang URL', value: f.url_length + ' karakter', flag: f.url_length > 75},
                {label: 'Menggunakan HTTPS', value: f.is_https ? 'Ya ✓' : 'Tidak ✗', flag: !f.is_https},
                {label: 'IP di URL', value: f.has_ip ? 'Ya ⚠' : 'Tidak', flag: f.has_ip},
                {label: 'TLD Mencurigakan', value: f.suspicious_tld ? 'Ya ⚠' : 'Tidak', flag: f.suspicious_tld},
                {label: 'Keyword Phishing', value: f.phishing_keywords + ' ditemukan', flag: f.phishing_keywords > 0},
                {label: 'Jumlah Titik', value: f.num_dots, flag: f.num_dots > 4},
                {label: 'Tanda Hubung', value: f.num_hyphens, flag: f.num_hyphens > 2},
                {label: 'Subdomain', value: f.subdomain_count, flag: f.subdomain_count > 2},
            ];
            featureItems.forEach(item => {
                const div = document.createElement('div');
                div.className = 'flex justify-between items-center py-1.5 border-b border-slate-700/40 last:border-0';
                div.innerHTML = '<span class="text-xs text-slate-400">'+item.label+'</span><span class="text-xs font-medium '+(item.flag?'text-red-400':'text-green-400')+'">'+item.value+'</span>';
                featuresList.appendChild(div);
            });
            if (data._fallback || !data.models_used) {
                const note = document.createElement('p');
                note.className = 'text-xs text-slate-600 mt-3 italic';
                note.textContent = '* Mode heuristic (jalankan phishing_service.py untuk ML detection)';
                featuresList.appendChild(note);
            }

            document.getElementById('result').classList.remove('hidden');
            document.getElementById('result').scrollIntoView({behavior: 'smooth'});
        }

        function resetForm() {
            document.getElementById('result').classList.add('hidden');
            document.getElementById('aiAnalysisSection').classList.add('hidden');
            document.getElementById('aiResult').innerHTML = '';
            document.getElementById('urlInput').value = '';
            lastScanResult = null;
            lastScanUrl = null;
            document.getElementById('urlInput').focus();
        }

        async function getAiAnalysis(url, scanResult) {
            var section  = document.getElementById('aiAnalysisSection');
            var loading  = document.getElementById('aiLoading');
            var resultDiv = document.getElementById('aiResult');
            section.classList.remove('hidden');
            loading.classList.remove('hidden');
            resultDiv.classList.add('hidden');
            resultDiv.innerHTML = '';
            try {
                var resp = await fetch('/api/phishing/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url, result: scanResult})
                });
                if (!resp.ok) throw new Error('HTTP ' + resp.status);
                var data = await resp.json();
                var ai = data.ai_analysis || {error: 'Tidak ada respons AI'};
                resultDiv.innerHTML = renderAiAnalysis(ai, scanResult.level || 'safe');
            } catch(e) {
                resultDiv.innerHTML = renderAiAnalysis({error: 'Tidak dapat menghubungi layanan AI: ' + e.message}, 'safe');
            } finally {
                loading.classList.add('hidden');
                resultDiv.classList.remove('hidden');
            }
        }

        function escHtml(str) {
            return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function renderAiAnalysis(ai, level) {
            var colors = {
                'danger':  {border:'border-red-500/30',    bg:'bg-red-500/5',    accent:'text-red-400',    badgeBg:'bg-red-500/15',    badgeBorder:'border-red-500/25'},
                'warning': {border:'border-yellow-500/30', bg:'bg-yellow-500/5', accent:'text-yellow-400', badgeBg:'bg-yellow-500/15', badgeBorder:'border-yellow-500/25'},
                'safe':    {border:'border-green-500/30',  bg:'bg-green-500/5',  accent:'text-green-400',  badgeBg:'bg-green-500/15',  badgeBorder:'border-green-500/25'}
            };
            var c = colors[level] || colors['safe'];

            if (ai.error) {
                return '<div class="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-5">' +
                    '<div class="flex items-center space-x-3">' +
                    '<span class="text-2xl">⚠️</span>' +
                    '<div><p class="text-sm font-medium text-slate-300">AI Analysis Tidak Tersedia</p>' +
                    '<p class="text-xs text-slate-500 mt-0.5">' + escHtml(ai.error) + '</p></div></div></div>';
            }

            var actionsHtml = '';
            if (ai.saran_tindakan && ai.saran_tindakan.length) {
                for (var i = 0; i < ai.saran_tindakan.length; i++) {
                    var num = (i + 1 < 10 ? '0' : '') + (i + 1);
                    actionsHtml += '<div class="flex items-start space-x-3 py-3 border-b border-slate-700/30 last:border-0">' +
                        '<span class="flex-shrink-0 w-7 h-7 rounded-full bg-purple-500/20 text-purple-400 text-xs font-bold flex items-center justify-center mt-0.5">' + num + '</span>' +
                        '<span class="text-sm text-slate-300 leading-relaxed">' + escHtml(ai.saran_tindakan[i]) + '</span></div>';
                }
            }

            var warningsHtml = '';
            if (ai.tanda_peringatan && ai.tanda_peringatan.length) {
                for (var j = 0; j < ai.tanda_peringatan.length; j++) {
                    warningsHtml += '<span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-orange-500/15 text-orange-400 border border-orange-500/25">' +
                        '<svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>' +
                        escHtml(ai.tanda_peringatan[j]) + '</span>';
                }
            }

            return '<div class="bg-slate-800/60 ' + c.border + ' border rounded-2xl overflow-hidden">' +

                '<div class="px-6 py-4 bg-slate-900/60 border-b border-slate-700/40 flex items-center justify-between">' +
                '<div class="flex items-center space-x-3">' +
                '<div class="w-9 h-9 rounded-xl bg-purple-500/20 flex items-center justify-center">' +
                '<svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>' +
                '</div>' +
                '<div><p class="text-sm font-bold text-white">AI Threat Intelligence</p><p class="text-xs text-slate-500">Analisis mendalam oleh Groq LLM</p></div>' +
                '</div>' +
                '<span class="text-xs font-semibold px-3 py-1 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/25 flex items-center gap-1.5">' +
                '<svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3zM6 8a2 2 0 11-4 0 2 2 0 014 0zM16 18v-3a5.972 5.972 0 00-.75-2.906A3.005 3.005 0 0119 15v3h-3zM4.75 12.094A5.973 5.973 0 004 15v3H1v-3a3 3 0 013.75-2.906z"></path></svg>' +
                'Groq AI</span>' +
                '</div>' +

                '<div class="p-6 space-y-6">' +

                '<div class="' + c.bg + ' border ' + c.border + ' rounded-xl p-4">' +
                '<p class="text-xs font-bold uppercase tracking-widest ' + c.accent + ' mb-2 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>' +
                'Ringkasan Eksekutif</p>' +
                '<p class="text-sm text-slate-200 leading-relaxed">' + escHtml(ai.ringkasan || '-') + '</p>' +
                '</div>' +

                '<div class="bg-slate-900/30 rounded-xl p-4 border border-slate-700/30">' +
                '<p class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>' +
                'Analisis Mendalam</p>' +
                '<p class="text-sm text-slate-300 leading-relaxed">' + escHtml(ai.analisis_detail || '-') + '</p>' +
                '</div>' +

                '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">' +
                '<div class="bg-slate-900/40 rounded-xl p-4 border border-slate-700/30">' +
                '<p class="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>' +
                'Target Korban</p>' +
                '<p class="text-sm text-slate-300 leading-relaxed">' + escHtml(ai.target_korban || 'Tidak teridentifikasi') + '</p>' +
                '</div>' +
                '<div class="bg-slate-900/40 rounded-xl p-4 border border-slate-700/30">' +
                '<p class="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>' +
                'Tingkat Bahaya</p>' +
                '<p class="text-sm ' + c.accent + ' leading-relaxed font-semibold">' + escHtml(ai.tingkat_bahaya || '-') + '</p>' +
                '</div>' +
                '</div>' +

                (warningsHtml ? '<div>' +
                '<p class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' +
                'Tanda Peringatan</p>' +
                '<div class="flex flex-wrap gap-2">' + warningsHtml + '</div></div>' : '') +

                (actionsHtml ? '<div>' +
                '<p class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path></svg>' +
                'Saran Tindakan</p>' +
                '<div>' + actionsHtml + '</div></div>' : '') +

                '<div class="rounded-xl p-4 border-l-4 border-purple-500/60 bg-purple-500/5">' +
                '<p class="text-xs font-bold uppercase tracking-widest text-purple-400 mb-2 flex items-center gap-1.5">' +
                '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>' +
                'Kesimpulan</p>' +
                '<p class="text-sm text-slate-200 leading-relaxed">' + escHtml(ai.kesimpulan || '-') + '</p>' +
                '</div>' +

                '</div>' +
            '</div>';
        }

        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') checkPhishing();
        });
    </script>
</body>
</html>
`
