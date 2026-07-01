package ai

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

        "domainscorer/internal/config"
        "domainscorer/internal/normalize"

        "github.com/sashabaranov/go-openai"
)

// AIClient defines the interface for an AI analysis client.
type AIClient interface {
        AnalyzeFindings(ctx context.Context, target string, findings []normalize.Finding) (*AnalysisResponse, error)
        GenerateGlobalSummary(ctx context.Context, target string, providerAnalyses []ProviderAnalysis) (*GlobalAnalysisResponse, error)
}

// GlobalAnalysisResponse defines the structure for the aggregated summary.
type GlobalAnalysisResponse struct {
        GlobalSummary     string   `json:"global_summary"`
        GlobalImpact      string   `json:"global_impact"`
        GlobalRemediation []string `json:"global_remediation"`
}

// client implements the AIClient interface.
type client struct {
        cfg          *config.AIConfig
        openaiClient *openai.Client
        httpClient   *http.Client
}

// NewAIClient creates a new client for AI analysis.
func NewAIClient(cfg *config.AIConfig) (AIClient, error) {
        if cfg == nil || !cfg.Enabled {
                return nil, fmt.Errorf("AI analysis is not enabled in the configuration")
        }

        switch cfg.Provider {
        case "gemini":
                if cfg.APIKey == "" {
                        return nil, fmt.Errorf("Gemini API key is not configured (check GEMINI_API_KEY)")
                }
                return &client{
                        cfg:        cfg,
                        httpClient: &http.Client{Timeout: 60 * time.Second},
                }, nil

        case "openai", "groq":
                if cfg.APIKey == "" {
                        return nil, fmt.Errorf("%s API key is not configured", cfg.Provider)
                }
                oaiCfg := openai.DefaultConfig(cfg.APIKey)
                if cfg.Provider == "groq" {
                        oaiCfg.BaseURL = "https://api.groq.com/openai/v1"
                }
                return &client{cfg: cfg, openaiClient: openai.NewClientWithConfig(oaiCfg)}, nil

        default:
                return nil, fmt.Errorf("unknown AI provider '%s'", cfg.Provider)
        }
}

// callGeminiREST calls Gemini via plain HTTP REST (no gRPC dependency).
func (c *client) callGeminiREST(ctx context.Context, prompt string) (string, error) {
        type part struct {
                Text string `json:"text"`
        }
        type content struct {
                Parts []part `json:"parts"`
        }
        type reqBody struct {
                Contents []content `json:"contents"`
        }

        body, _ := json.Marshal(reqBody{
                Contents: []content{{Parts: []part{{Text: prompt}}}},
        })

        model := c.cfg.Model
        if model == "" {
                model = "gemini-2.5-flash"
        }
        url := fmt.Sprintf(
                "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
                model, c.cfg.APIKey,
        )

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
        if err != nil {
                return "", err
        }
        req.Header.Set("Content-Type", "application/json")

        resp, err := c.httpClient.Do(req)
        if err != nil {
                return "", fmt.Errorf("Gemini HTTP request failed: %w", err)
        }
        defer resp.Body.Close()

        raw, _ := io.ReadAll(resp.Body)
        if resp.StatusCode != http.StatusOK {
                return "", fmt.Errorf("Gemini API error %d: %s", resp.StatusCode, string(raw))
        }

        var gemResp struct {
                Candidates []struct {
                        Content struct {
                                Parts []struct {
                                        Text string `json:"text"`
                                } `json:"parts"`
                        } `json:"content"`
                } `json:"candidates"`
        }
        if err := json.Unmarshal(raw, &gemResp); err != nil {
                return "", fmt.Errorf("failed to parse Gemini response: %w", err)
        }
        if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
                return "", fmt.Errorf("empty response from Gemini")
        }
        return gemResp.Candidates[0].Content.Parts[0].Text, nil
}

// callLLM dispatches to the right provider.
func (c *client) callLLM(ctx context.Context, prompt string) (string, error) {
        switch c.cfg.Provider {
        case "gemini":
                resp, err := c.callGeminiREST(ctx, prompt)
                if err != nil {
                        groqKey := os.Getenv("GROQ_API_KEY")
                        if groqKey != "" {
                                fmt.Printf("[!] Gemini API failed (%v), falling back to Groq...\n", err)
                                groqCfg := openai.DefaultConfig(groqKey)
                                groqCfg.BaseURL = "https://api.groq.com/openai/v1"
                                groqClient := openai.NewClientWithConfig(groqCfg)
                                
                                groqResp, groqErr := groqClient.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
                                        Model: "llama-3.3-70b-versatile",
                                        ResponseFormat: &openai.ChatCompletionResponseFormat{
                                                Type: openai.ChatCompletionResponseFormatTypeJSONObject,
                                        },
                                        Messages: []openai.ChatCompletionMessage{
                                                {Role: openai.ChatMessageRoleUser, Content: prompt},
                                        },
                                })
                                if groqErr == nil && len(groqResp.Choices) > 0 {
                                        return groqResp.Choices[0].Message.Content, nil
                                }
                                return "", fmt.Errorf("Gemini failed (%v) AND Groq fallback failed: %v", err, groqErr)
                        }
                        return "", err
                }
                return resp, nil
        case "openai", "groq":
                resp, err := c.openaiClient.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
                        Model: c.cfg.Model,
                        Messages: []openai.ChatCompletionMessage{
                                {Role: openai.ChatMessageRoleUser, Content: prompt},
                        },
                })
                if err != nil {
                        return "", fmt.Errorf("failed to generate content from %s: %w", c.cfg.Provider, err)
                }
                if len(resp.Choices) == 0 {
                        return "", fmt.Errorf("empty response from %s", c.cfg.Provider)
                }
                return resp.Choices[0].Message.Content, nil
        default:
                return "", fmt.Errorf("unhandled AI provider: %s", c.cfg.Provider)
        }
}

// AnalyzeFindings sends findings to the configured LLM and returns structured analysis.
func (c *client) AnalyzeFindings(ctx context.Context, target string, findings []normalize.Finding) (*AnalysisResponse, error) {
        inputMap := map[string]any{"target": target, "findings": findings}
        inputJSON, err := json.MarshalIndent(inputMap, "", "  ")
        if err != nil {
                return nil, fmt.Errorf("failed to marshal findings: %w", err)
        }

        prompt := fmt.Sprintf(`
ROLE

You are a Senior Cyber Risk Auditor. Your objective is to perform a Contextual Risk Assessment on External Attack Surface Management (EASM) data aggregated from multiple CTI sources (LeakIX, Shodan, Censys, Fofa).

PHILOSOPHY

You act as a filter between raw data and executive decision-making. You must avoid "Severity Inflation". A vulnerability is only "Critical" if it is reachable, exploitable, and impacts business continuity or data privacy.

OBJECTIVE STANDARDS

Your analysis MUST adhere to:

CVSS v3.1/v4.0 Severity: For technical impact assessment.

CISA KEV (Known Exploited Vulnerabilities): Prioritize vulnerabilities currently exploited in the wild.

EPSS (Exploit Prediction Scoring System): Use to weigh the likelihood of a CVE being exploited.

OWASP Top 10: Categorize misconfigurations (A01: Broken Access Control, A05: Security Misconfiguration).

SCORING LOGIC (RISK-BASED)

9.0 - 10.0 (CRITICAL - Active/Immediate Breach):

Verified leakage of ACTIVE credentials (DB_PASSWORD, API_KEY) in cleartext.

Verified leakage of PII (NIK, KTP, KK, Passports) via directory listing/open buckets.

Remote Code Execution (RCE) vulnerabilities listed in CISA KEV.

7.0 - 8.9 (HIGH - High Exploitation Probability):

Unprotected Administrative Panels (Login pages) for critical infrastructure.

Sensitive file exposure (e.g., .env, .git) containing system structure/internal IPs, even if credentials are not immediately clear.

High-impact CVEs (CVSS > 8.0) with High EPSS score (> 0.3) on verified services.

4.0 - 6.9 (MEDIUM - Tactical Exposure):

Detailed Information Disclosure (Apache/Nginx Status, phpinfo()).

Directory listings exposing non-sensitive system files (.DS_Store, build logs).

Outdated software versions with no public exploit or low EPSS.

0.1 - 3.9 (LOW - Technical Debt):

Standard service exposure (80/443), version disclosure of patched services, weak SSL/TLS ciphers.

CRITICAL EVIDENCE VALIDATION (ANTI-NOISE)

The Template Rule: If a file (like .env) contains only comments (#) or default examples (e.g., DB_PASSWORD=root), DO NOT score as Critical. Score as HIGH/MEDIUM for "Information Disclosure" and "Improper Asset Management".

The Backporting Rule: Be skeptical of version banners (Shodan/Censys). Distinguish between a "Potential Vulnerability" (banner only) and a "Verified Vulnerability" (scanner confirmed).

PII Context: Verify if the data is intended for public consumption (e.g., Public Employee Directory) vs sensitive PII (Identity documents).

OUTPUT REQUIREMENT (STRICT JSON)

Response must be a SINGLE valid JSON object.

{
"target": "string",
"aggregated_risk_score": float (0.0-10.0),
"risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
"confidence_score": float (0.0-1.0),
"analysis_summary": "Professional executive summary focusing on verified impact. Max 3 sentences.",
"findings_analysis": [
{
"asset": "string",
"source": "string",
"standard_ref": "CVSS/CISA-KEV/OWASP",
"objective_finding": "Short description of the verified evidence.",
"score": float,
"logic": "Explanation of why this score was given, specifically mentioning if it's based on raw evidence or just a banner."
}
],
"potential_impact": "Realistic worst-case scenario (e.g., 'Targeted ransomware entry point via exposed VPN config').",
"remediation_roadmap": [
"Immediate technical step based on verified risk."
]
}

INPUT DATA:
%s
`, string(inputJSON))

        rawResponse, err := c.callLLM(ctx, prompt)
        if err != nil {
                return nil, err
        }

        cleanResp := cleanJSON(rawResponse)
        var result AnalysisResponse
        if err := json.Unmarshal([]byte(cleanResp), &result); err != nil {
                return nil, fmt.Errorf("failed to parse AI response: %w (raw: %s)", err, cleanResp)
        }
        return &result, nil
}

// GenerateGlobalSummary creates an executive summary from all provider analyses.
func (c *client) GenerateGlobalSummary(ctx context.Context, target string, providerAnalyses []ProviderAnalysis) (*GlobalAnalysisResponse, error) {
        inputMap := map[string]any{"target": target, "provider_analyses": providerAnalyses}
        inputJSON, err := json.MarshalIndent(inputMap, "", "  ")
        if err != nil {
                return nil, fmt.Errorf("failed to marshal provider analyses: %w", err)
        }

        prompt := fmt.Sprintf(`
ROLE

You are a Chief Information Security Officer (CISO). Your objective is to synthesize technical findings from multiple CTI sources (LeakIX, Shodan, Censys, etc.) into a cohesive Executive Risk Assessment.

INPUT DATA

You are provided with a list of "Provider Analyses". Each provider has already analyzed a specific subset of the attack surface. Your job is NOT to re-analyze raw data, but to AGGREGATE and SUMMARIZE their findings into a global narrative.

OBJECTIVE

1.  Identify Cross-Cutting Themes: If multiple providers report the same open port or vulnerability, highlight this as a corroborated fact.
2.  Executive Summary: Write a high-level narrative (3-5 sentences) that explains the overall risk posture. Avoid technical jargon where possible, focusing on business risk.
3.  Global Impact: Describe the worst-case scenario if the identified risks are exploited.
4.  Consolidated Remediation: unique, high-priority action items.

OUTPUT REQUIREMENT (STRICT JSON)

{
  "global_summary": "The target domain exhibits...",
  "global_impact": "Potential for unauthorized access...",
  "global_remediation": [
    "Immediate action 1...",
    "Strategic action 2..."
  ]
}

INPUT:
%s
`, string(inputJSON))

        rawResponse, err := c.callLLM(ctx, prompt)
        if err != nil {
                return nil, err
        }

        cleanResp := cleanJSON(rawResponse)
        var result GlobalAnalysisResponse
        if err := json.Unmarshal([]byte(cleanResp), &result); err != nil {
                return nil, fmt.Errorf("failed to parse AI global summary: %w (raw: %s)", err, cleanResp)
        }
        return &result, nil
}

// cleanJSON sanitizes the raw string response from the AI.
func cleanJSON(s string) string {
        s = strings.TrimSpace(s)
        
        // Find the first '{' and last '}'
        start := strings.Index(s, "{")
        end := strings.LastIndex(s, "}")
        
        if start != -1 && end != -1 && end > start {
                return s[start : end+1]
        }
        
        // Fallback to original trimming if brackets aren't found properly
        s = strings.TrimPrefix(s, "```json")
        s = strings.TrimPrefix(s, "```")
        s = strings.TrimSuffix(s, "```")
        return strings.TrimSpace(s)
}
