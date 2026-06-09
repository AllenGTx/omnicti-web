package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"time"

	"domainscorer/internal/config"
	"domainscorer/internal/core"
	"domainscorer/internal/ctisource/base"
	"domainscorer/internal/ctisource/censys"
	"domainscorer/internal/ctisource/leakix"
	"domainscorer/internal/ctisource/shodan"
	"domainscorer/internal/ctisource/virustotal"
	"domainscorer/internal/normalize"
	"domainscorer/internal/scoring"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: experiment <domains_file.txt>")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		d := scanner.Text()
		if d != "" {
			domains = append(domains, d)
		}
	}

	config.Load()
	if err := config.LoadScoring("internal/config/scoring.yaml"); err != nil {
		log.Fatalf("Error loading scoring config: %v", err)
	}

	// Setup Sources
	sources := []base.Source{
		leakix.NewSource(),
		shodan.NewSource(),
		censys.NewSource(),
		virustotal.NewSource(),
	}

	// Prepare CSV Output
	outName := fmt.Sprintf("experiment_results_%d.csv", time.Now().Unix())
	outFile, err := os.Create(outName)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	// Header: Domain, Baseline_CVSS, CTI_NoDecay, CTI_WithDecay
	writer.Write([]string{"Domain", "Baseline_CVSS", "CTI_NoDecay", "CTI_WithDecay", "Findings_Count"})

	ctx := context.Background()

	fmt.Printf("[*] Running experiment on %d domains...\n", len(domains))

	for i, domain := range domains {
		fmt.Printf("[%d/%d] Analyzing %s...\n", i+1, len(domains), domain)

		// 1. Run Engine
		findings, err := core.Run(ctx, domain, sources)
		if err != nil {
			log.Printf("Error analyzing %s: %v\n", domain, err)
			continue
		}

		findings = normalize.Dedup(findings)

		// 2. Calculate Scores
		scoreBaseline := calculateBaseline(findings)
		scoreNoDecay := calculateNoDecay(findings)
		scoreWithDecay := scoring.Aggregate(findings) // Uses current ScoreFinding

		// 3. Write Row
		writer.Write([]string{
			domain,
			fmt.Sprintf("%.2f", scoreBaseline),
			fmt.Sprintf("%.2f", scoreNoDecay),
			fmt.Sprintf("%.2f", scoreWithDecay),
			strconv.Itoa(len(findings)),
		})
		writer.Flush() // Flush often so we can see progress
	}

	fmt.Printf("[+] Experiment complete. Results saved to %s\n", outName)
}

// Baseline: Pure BaseScore (Severity) sum, without decay, reliability, or multiplier.
// Simulates "CVSS only" (Static).
func calculateBaseline(fs []normalize.Finding) float64 {
	sum := 0.0
	for _, f := range fs {
		// Just Severity -> BaseScore
		// Assuming f.BaseScore IS based on severity map (10-100)
		sum += f.BaseScore
	}
	return math.Min(100.0, sum)
}

// NoDecay: Includes Reliability & Multiplier, but Time/Decay factor is always 1.0.
// Simulates "CTI without aging".
func calculateNoDecay(fs []normalize.Finding) float64 {
	sum := 0.0
	for _, f := range fs {
		// Recalculate component
		base := f.BaseScore

		multiplier := f.Multiplier
		if multiplier == 0 {
			multiplier = scoring.BusinessLogicMultiplier(f.Type, f.Evidence)
		}

		reliability := scoring.SourceReliability(f.Source)

		// Decay is ignored (effectively 1.0)

		sum += base * multiplier * reliability
	}
	return math.Min(100.0, sum)
}
