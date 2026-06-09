package aggregation

import (
	"domainscorer/internal/ai"
	"domainscorer/internal/normalize"
	"domainscorer/internal/scoring"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Result represents the final output of the domain scan.
// It includes the domain, the calculated risk score (0-100), the risk level (Low-Critical),
// the individual findings from CTI sources, and the optional AI-driven analysis.
type Result struct {
	Domain     string                 `json:"domain"`
	Score      float64                `json:"score"`
	Level      string                 `json:"level"`
	Findings   []normalize.Finding    `json:"findings"`
	AIAnalysis *ai.AggregatedAnalysis `json:"ai_analysis,omitempty"`
}

// Build creates a new Result object.
// It assigns the domain, score, and findings, and automatically calculates the risk level.
func Build(domain string, score float64, findings []normalize.Finding) Result {
	// Calculate Score (Deterministic) - Now aligned with AI comparison logic
	calculatedScore := scoring.Aggregate(findings)
	calculatedLevel := InterpretLevel(calculatedScore)

	return Result{
		Domain:   domain,
		Score:    calculatedScore,
		Level:    calculatedLevel,
		Findings: findings,
	}
}

// InterpretLevel maps a numeric risk score (0-100) to a textual risk level.
// Levels: Critical (80+), High (60+), Medium (30+), Low (<30).
func InterpretLevel(score float64) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= 60:
		return "High"
	case score >= 30:
		return "Medium"
	default:
		return "Low"
	}
}

// PrintJSON outputs the Result struct as a formatted JSON string to stdout.
func (r Result) PrintJSON() {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Printf("{\"error\": \"failed to marshal result: %v\"}\n", err)
		return
	}
	fmt.Println(string(b))
}

// Print outputs a human-readable text report to stdout.
// It includes the score, level, AI analysis summary (if available), and a detailed list of findings.
func (r Result) Print() {
	fmt.Printf("\n=== Domain Risk Report: %s ===\n", r.Domain)
	fmt.Printf("Risk Score: %.1f [%s]\n", r.Score, r.Level)

	// AI Section
	// AI Section
	if r.AIAnalysis != nil {
		fmt.Printf("AI Total Risk Score: %.1f/100.0 [%s]\n", r.AIAnalysis.FinalScore, r.AIAnalysis.RiskLevel)

		for _, p := range r.AIAnalysis.Providers {
			fmt.Printf("\n  --- Provider: %s (Contrib: %.1f) ---\n", p.Provider, p.Contribution)
			if p.Error != "" {
				fmt.Printf("  [!] Error: %s\n", p.Error)
				continue
			}
			if p.Analysis != nil {
				fmt.Printf("  Summary: %s\n", p.Analysis.AnalysisSummary)
				if len(p.Analysis.FindingsAnalysis) > 0 {
					for _, fa := range p.Analysis.FindingsAnalysis {
						fmt.Printf("   - [%s] %s (Score: %.1f)\n", fa.StandardRef, fa.ObjectiveFinding, fa.Score)
					}
				}
			}
		}
	}

	fmt.Printf("\nTotal Findings: %d\n", len(r.Findings))
	// ... rest of Print functions ... (Keep existing code from line 58 onwards)
	fmt.Println("\n--- Findings by Source ---")
	counts := make(map[string]int)
	for _, f := range r.Findings {
		counts[f.Source]++
	}
	// Sort sources for consistent output
	var sources []string
	for s := range counts {
		sources = append(sources, s)
	}
	sort.Strings(sources)

	if len(sources) == 0 {
		fmt.Println("(No findings detected from any source)")
	}
	for _, s := range sources {
		fmt.Printf("- %s: %d\n", s, counts[s])
	}
	fmt.Println("(Note: Sources not listed returned 0 findings or failed. Check logs.)")

	fmt.Println("------------------------------------------------")

	// 2. Findings Detail
	// Sort by score descending (re-calculating score for sort is expensive, but for print it's fine)
	// Or we just assume they are roughly ordered or just print top 10.

	for i, f := range r.Findings {
		if i >= 10 {
			fmt.Printf("... (more findings hidden)\n")
			break
		}

		// Recalculate components for display
		base := f.BaseScore
		if base == 0 {
			base = scoring.SeverityScore(f.Severity)
		}

		mult := f.Multiplier
		if mult == 0 {
			mult = scoring.BusinessLogicMultiplier(f.Type, f.Evidence)
		}

		rel := scoring.SourceReliability(f.Source)
		decay := scoring.TemporalDecay(f.ObservedAt)
		final := scoring.ScoreFinding(f)

		// Display format: [Severity] Type (Source) - Score
		fmt.Printf("[%s] %s (%s)\n", f.Severity, f.Type, f.Source)

		// Evidence snippet
		var evidence []string
		for k, v := range f.Evidence {
			// Limit evidence length
			val := fmt.Sprintf("%v", v)
			if len(val) > 50 {
				val = val[:47] + "..."
			}
			evidence = append(evidence, fmt.Sprintf("%s: %s", k, val))
		}
		if len(evidence) > 0 {
			fmt.Printf("  Evidence: {%s}\n", strings.Join(evidence, ", "))
		}

		// Formula Breakdown
		fmt.Printf("  Score: %.2f (Base: %.0f x Mult: %.1f x Rel: %.1f x Decay: %.2f)\n",
			final, base, mult, rel, decay)
		fmt.Println("")
	}
}
