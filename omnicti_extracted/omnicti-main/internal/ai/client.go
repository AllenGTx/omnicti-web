package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"domainscorer/internal/config"
	"domainscorer/internal/normalize"

	"github.com/google/generative-ai-go/genai"
	"github.com/sashabaranov/go-openai"
	"google.golang.org/api/option"
)

// AIClient defines the interface for an AI analysis client.
// It abstracts the underlying AI provider (Gemini, OpenAI, Groq) to allow interchangeable use.
type AIClient interface {
	// AnalyzeFindings sends a list of findings to the configured AI provider for risk assessment.
	// It returns a structured AnalysisResponse containing risk scores, summaries, and remediation steps.
	AnalyzeFindings(ctx context.Context, target string, findings []normalize.Finding) (*AnalysisResponse, error)

	// GenerateGlobalSummary synthesizes the individual provider analyses into a single executive summary.
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
	geminiClient *genai.GenerativeModel
	openaiClient *openai.Client // Used for both OpenAI and Groq
}

// NewAIClient creates a new client for AI analysis based on the provided configuration.
// It initializes the appropriate client (Gemini, OpenAI, or Groq) based on the 'Provider' field in the config.
// Returns an error if the configuration is missing, disabled, or if the API key is not set.
func NewAIClient(cfg *config.AIConfig) (AIClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("AI analysis is not enabled in the configuration")
	}

	switch cfg.Provider {
	case "gemini":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("Gemini API key is not configured (check .env GEMINI_API_KEY)")
		}
		ctx := context.Background()
		genaiClient, err := genai.NewClient(ctx, option.WithAPIKey(cfg.APIKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create Gemini client: %w", err)
		}
		model := genaiClient.GenerativeModel(cfg.Model)
		return &client{cfg: cfg, geminiClient: model}, nil

	case "openai", "groq":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("%s API key is not configured (check .env)", cfg.Provider)
		}
		config := openai.DefaultConfig(cfg.APIKey)
		if cfg.Provider == "groq" {
			config.BaseURL = "https://api.groq.com/openai/v1"
		}
		openaiClient := openai.NewClientWithConfig(config)
		return &client{cfg: cfg, openaiClient: openaiClient}, nil

	default:
		return nil, fmt.Errorf("unknown AI provider '%s'", cfg.Provider)
	}
}

// AnalyzeFindings sends the findings to the configured LLM and returns its analysis.
// It constructs a detailed prompt including the findings and instructs the AI to act as a "Senior Cyber Risk Auditor".
// The response is expected to be a valid JSON object matching the AnalysisResponse struct.
func (c *client) AnalyzeFindings(ctx context.Context, target string, findings []normalize.Finding) (*AnalysisResponse, error) {
	// Prepare input JSON
	inputMap := map[string]any{
		"target":   target,
		"findings": findings,
	}
	inputJSON, err := json.MarshalIndent(inputMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal findings to JSON: %w", err)
	}

	// ---------------------------------------------------------
	// PROMPT DEFINITION
	// ---------------------------------------------------------
	// ---------------------------------------------------------
	// PROMPT DEFINITION
	// ---------------------------------------------------------
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

	// ---------------------------------------------------------
	// EXECUTE REQUEST
	// ---------------------------------------------------------

	var rawResponse string

	switch c.cfg.Provider {
	case "gemini":
		if c.geminiClient == nil {
			return nil, fmt.Errorf("Gemini client is not initialized")
		}
		resp, err := c.geminiClient.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			return nil, fmt.Errorf("failed to generate content from Gemini: %w", err)
		}
		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			return nil, fmt.Errorf("received an empty response from Gemini")
		}
		analysisResult, ok := resp.Candidates[0].Content.Parts[0].(genai.Text)
		if !ok {
			return nil, fmt.Errorf("unexpected response format from Gemini")
		}
		rawResponse = string(analysisResult)

	case "openai", "groq":
		if c.openaiClient == nil {
			return nil, fmt.Errorf("%s client is not initialized", c.cfg.Provider)
		}
		resp, err := c.openaiClient.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model: c.cfg.Model,
				Messages: []openai.ChatCompletionMessage{
					{
						Role:    openai.ChatMessageRoleUser,
						Content: prompt,
					},
				},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate content from %s: %w", c.cfg.Provider, err)
		}
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("received an empty response from %s", c.cfg.Provider)
		}
		rawResponse = resp.Choices[0].Message.Content

	default:
		return nil, fmt.Errorf("unhandled AI provider: %s", c.cfg.Provider)
	}

	cleanResp := cleanJSON(rawResponse)

	var result AnalysisResponse
	if err := json.Unmarshal([]byte(cleanResp), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w (raw: %s)", err, cleanResp)
	}

	return &result, nil
}

// cleanJSON sanitizes the raw string response from the AI.
// It removes markdown code block delimiters (```json ... ```) to extract the raw JSON string.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

// GenerateGlobalSummary creates an executive summary from all provider analyses.
func (c *client) GenerateGlobalSummary(ctx context.Context, target string, providerAnalyses []ProviderAnalysis) (*GlobalAnalysisResponse, error) {
	// Prepare input JSON
	inputMap := map[string]any{
		"target":            target,
		"provider_analyses": providerAnalyses,
	}
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

1.  **Identify Cross-Cutting Themes:** If multiple providers report the same open port or vulnerability, highlight this as a corroborated fact.
2.  **Executive Summary:** Write a high-level narrative (3-5 sentences) that explains the overall risk posture. Avoid technical jargon where possible, focusing on business risk.
3.  **Global Impact:** Describe the worst-case scenario if the identified risks are exploited.
4.  **Consolidated Remediation:** unique, high-priority action items.

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

	// Execute Request (Reuse logic from AnalyzeFindings - strictly creating a helper might be better but for now we duplicate the switch for speed and creating a helper would be a larger refactor)
	var rawResponse string

	switch c.cfg.Provider {
	case "gemini":
		if c.geminiClient == nil {
			return nil, fmt.Errorf("Gemini client is not initialized")
		}
		resp, err := c.geminiClient.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			return nil, fmt.Errorf("failed to generate content from Gemini: %w", err)
		}
		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			return nil, fmt.Errorf("received an empty response from Gemini")
		}
		analysisResult, ok := resp.Candidates[0].Content.Parts[0].(genai.Text)
		if !ok {
			return nil, fmt.Errorf("unexpected response format from Gemini")
		}
		rawResponse = string(analysisResult)

	case "openai", "groq":
		if c.openaiClient == nil {
			return nil, fmt.Errorf("%s client is not initialized", c.cfg.Provider)
		}
		resp, err := c.openaiClient.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model: c.cfg.Model,
				Messages: []openai.ChatCompletionMessage{
					{
						Role:    openai.ChatMessageRoleUser,
						Content: prompt,
					},
				},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate content from %s: %w", c.cfg.Provider, err)
		}
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("received an empty response from %s", c.cfg.Provider)
		}
		rawResponse = resp.Choices[0].Message.Content

	default:
		return nil, fmt.Errorf("unhandled AI provider: %s", c.cfg.Provider)
	}

	cleanResp := cleanJSON(rawResponse)

	var result GlobalAnalysisResponse
	if err := json.Unmarshal([]byte(cleanResp), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI global summary: %w (raw: %s)", err, cleanResp)
	}

	return &result, nil
}
