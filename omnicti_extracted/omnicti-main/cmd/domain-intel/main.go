package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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
	"domainscorer/internal/server"
)

// main is the entry point for the domain-intel CLI and Web Server.
// It supports two modes:
// 1. Web Server (-http flag): Starts an HTTP server for interactive scanning.
// 2. CLI Scan (default): Runs a one-off scan against a target domain and outputs findings.
func main() {
	// Flags
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	reportFile := flag.String("report", "", "Output path for HTML report")
	httpAddr := flag.String("http", "", "Start web server on address (e.g., :8080)")
	configFile := flag.String("config", "internal/config/scoring.yaml", "Path to scoring configuration file")
	verbose := flag.Bool("v", false, "Enable verbose output")

	// Custom Usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
OmniCTI: Cross-Platform Intelligence Aggregation with AI-Driven Risk Judgement
--------------------------------------------------------------------------
A CTI-driven framework for quantifying external domain risk.

Sources: LeakIX, Shodan, Censys, VirusTotal, AlienVault
AI Support: Gemini, OpenAI, Groq

Usage: domain-intel [options] <domain>

Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  domain-intel example.com
  domain-intel -report report.html example.com
  domain-intel -http :8080
  domain-intel -json -v example.com > report.json
  domain-intel -config my_scoring.yaml example.com
`)
	}

	flag.Parse()

	// 0. Load Config (needed for both modes)
	config.Load()
	if err := config.LoadScoring(*configFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scoring config from %s: %v\n", *configFile, err)
		os.Exit(1)
	}

	// Mode 1: Web Server
	if *httpAddr != "" {
		if err := server.Start(*httpAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Mode 2: CLI Scan
	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	domain := flag.Arg(0)
	ctx := context.Background()

	// 1. Setup Sources
	if config.CurrentScoringConfig.AI.Enabled {
		if *verbose && !*jsonOutput {
			fmt.Printf("[DEBUG] AI Enabled: true, Provider: %s\n", config.CurrentScoringConfig.AI.Provider)
		}
	} else {
		if *verbose && !*jsonOutput {
			fmt.Printf("[DEBUG] AI Enabled: false\n")
		}
	}

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

	// 2. Run Engine (Discovery + Fetch + Map)
	if !*jsonOutput {
		fmt.Printf("[*] Starting analysis for %s...\n", domain)
	}
	findings, err := core.Run(ctx, domain, sources)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// 3. Deduplication
	findings = normalize.Dedup(findings)

	// 4. Scoring & Aggregation
	score := scoring.Aggregate(findings)

	// 5. AI Analysis (Per-Provider)
	// This section aggregates risk scores from multiple CTI providers using Generative AI.
	var aggregatedAnalysis *ai.AggregatedAnalysis

	aiCfg := &config.CurrentScoringConfig.AI
	if aiCfg.Enabled {
		aggregatedAnalysis = &ai.AggregatedAnalysis{
			Providers:  []ai.ProviderAnalysis{},
			Timestamp:  time.Now().Format(time.RFC3339),
			RiskLevel:  "Unknown",
			FinalScore: 0.0,
		}

		// Populate API Key from Env based on selected provider
		switch aiCfg.Provider {
		case "gemini":
			aiCfg.APIKey = os.Getenv("GEMINI_API_KEY")
		case "openai":
			aiCfg.APIKey = os.Getenv("OPENAI_API_KEY")
		case "groq":
			aiCfg.APIKey = os.Getenv("GROQ_API_KEY")
		}

		if *verbose && !*jsonOutput {
			fmt.Printf("[*] Running AI Risk Analysis (%s)...\n", aiCfg.Provider)
		}

		aiClient, err := ai.NewAIClient(aiCfg)
		if err != nil {
			errMsg := fmt.Sprintf("AI Init Failed: %v", err)
			if *verbose {
				fmt.Fprintf(os.Stderr, "[!] %s\n", errMsg)
			}
		} else {
			// 1. Group findings by source to isolate analysis contexts.
			findingsBySource := make(map[string][]normalize.Finding)
			for _, f := range findings {
				findingsBySource[f.Source] = append(findingsBySource[f.Source], f)
			}

			totalContribution := 0.0
			// 2. Iterate over each source and perform independent AI analysis.
			for source, sourceFindings := range findingsBySource {
				pAnalysis := ai.ProviderAnalysis{
					Provider: source,
				}
				if *verbose {
					fmt.Fprintf(os.Stderr, "   > Analyzing findings from %s...\n", source)
				}
				analysis, err := aiClient.AnalyzeFindings(ctx, domain, sourceFindings)
				if err != nil {
					pAnalysis.Error = err.Error()
					if *verbose {
						fmt.Fprintf(os.Stderr, "     [!] Failed: %v\n", err)
					}
				} else {
					pAnalysis.Analysis = analysis
					// Calculate weighted contribution (max 20 points per provider).
					contrib := analysis.AggregatedRiskScore * 2.0
					pAnalysis.Contribution = contrib
					totalContribution += contrib
				}
				aggregatedAnalysis.Providers = append(aggregatedAnalysis.Providers, pAnalysis)
			}

			// 3. Cap Total Score at 100.
			if totalContribution > 100.0 {
				totalContribution = 100.0
			}
			aggregatedAnalysis.FinalScore = totalContribution
			aggregatedAnalysis.RiskLevel = aggregation.InterpretLevel(totalContribution)

			// 4. Generate Global Executive Summary
			if len(aggregatedAnalysis.Providers) > 0 {
				if *verbose && !*jsonOutput {
					fmt.Fprintf(os.Stderr, "   > Generating Global Executive Summary...\n")
				}
				globalSummary, err := aiClient.GenerateGlobalSummary(ctx, domain, aggregatedAnalysis.Providers)
				if err != nil {
					if *verbose {
						fmt.Fprintf(os.Stderr, "     [!] Failed to generate global summary: %v\n", err)
					}
				} else {
					aggregatedAnalysis.GlobalSummary = globalSummary.GlobalSummary
					aggregatedAnalysis.GlobalImpact = globalSummary.GlobalImpact
					aggregatedAnalysis.GlobalRemediation = globalSummary.GlobalRemediation
				}
			}
		}

	}

	// 6. Result Building
	result := aggregation.Build(domain, score, findings)
	result.AIAnalysis = aggregatedAnalysis
	// Note: We do NOT overwrite result.Score with AI score anymore.
	// We want to see the deterministic score (Result.Score) AND the AI score (Result.AIAnalysis.FinalScore).

	// 7. Report Generation
	if *reportFile != "" {
		if !*jsonOutput {
			fmt.Printf("[*] Generating HTML report to %s...\n", *reportFile)
		}
		if err := report.GenerateHTMLReport(result, *reportFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		} else {
			if !*jsonOutput {
				fmt.Printf("[+] Report saved to %s\n", *reportFile)
			}
		}
	}

	// 8. Output
	if *jsonOutput {
		result.PrintJSON()
	} else {
		result.Print()
	}
}
