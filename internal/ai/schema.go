package ai

// FindingAnalysis represents a detailed analysis of a specific finding.
// It maps the finding to standard frameworks (CVSS, OWASP) and provides a reasoned score.
type FindingAnalysis struct {
	Asset            string  `json:"asset"`
	Source           string  `json:"source"`
	StandardRef      string  `json:"standard_ref"` // CVSS/CISA-KEV/OWASP
	ObjectiveFinding string  `json:"objective_finding"`
	Score            float64 `json:"score"`
	Logic            string  `json:"logic"`
}

// AnalysisResponse defines the structure of the AI analysis output.
// It contains the high-level risk assessment, summary, and action items.
type AnalysisResponse struct {
	Target              string            `json:"target"`
	AggregatedRiskScore float64           `json:"aggregated_risk_score"` // 0.0 - 10.0 (Local score for this batch)
	RiskLevel           string            `json:"risk_level"`            // CRITICAL, HIGH, MEDIUM, LOW
	ConfidenceScore     float64           `json:"confidence_score"`      // 0.0 - 1.0
	AnalysisSummary     string            `json:"analysis_summary"`
	FindingsAnalysis    []FindingAnalysis `json:"findings_analysis"`
	PotentialImpact     string            `json:"potential_impact"`
	RemediationRoadmap  []string          `json:"remediation_roadmap"`
}

// ProviderAnalysis stores the analysis result for a single provider.
// It wraps the AI's AnalysisResponse with metadata about the contribution to the final score.
type ProviderAnalysis struct {
	Provider     string            `json:"provider"`
	Analysis     *AnalysisResponse `json:"analysis"`
	Contribution float64           `json:"contribution"` // Score contribution (max 20)
	Error        string            `json:"error,omitempty"`
}

// AggregatedAnalysis stores the combined analysis from all providers.
// It represents the final AI-driven risk assessment, summing up contributions from each provider.
type AggregatedAnalysis struct {
	Providers         []ProviderAnalysis `json:"providers"`
	FinalScore        float64            `json:"final_score"` // Sum of contributions, capped at 100
	RiskLevel         string             `json:"risk_level"`
	Timestamp         string             `json:"timestamp"`
	GlobalSummary     string             `json:"global_summary,omitempty"`
	GlobalImpact      string             `json:"global_impact,omitempty"`
	GlobalRemediation []string           `json:"global_remediation,omitempty"`
}
