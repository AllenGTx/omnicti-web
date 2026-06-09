package core

import (
	"context"
	"fmt"
	"os"
	"sync"

	"domainscorer/internal/ctisource/base"
	"domainscorer/internal/discovery"
	"domainscorer/internal/normalize"
)

// Run orchestrates the domain risk assessment.
// It performs discovery (resolve -> filter CDN) and then queries all configured CTI sources.
func Run(ctx context.Context, domain string, sources []base.Source) ([]normalize.Finding, error) {
	// 1. Discovery
	ips, err := discovery.Resolve(domain)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	// 2. Filter CDN
	originIPs := discovery.FilterCDN(ips)

	// Combine targets: domain itself + origin IPs
	// Some CTI sources check domain, others check IP.
	// For LeakIX, we are using domain endpoint, but we pass valid asset info.
	targets := []string{domain}
	for _, ip := range originIPs {
		targets = append(targets, ip.String())
	}

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		allFindings []normalize.Finding
	)

	// 3. Run CTI Sources
	// We run each source against valid targets found.
	// For simplicity, let's assume sources can handle domain or IP,
	// or we just query the domain for now as per blueprint basic flow (Step 4 says "Run all CTI source... raw := source.Fetch(ctx, domainOrIP)").
	// Given LeakIX implementation uses domain endpoint, we'll primarily query the domain.
	// But if we had IP-based sources (like Shodan IP scan), we would loop over IPs too.
	// Let's loop sources and pass the domain, but strictly speaking finding assets might be IPs.

	for _, src := range sources {
		wg.Add(1)
		go func(s base.Source) {
			defer wg.Done()

			// Fetch data
			raw, err := s.Fetch(ctx, domain)
			if err != nil {
				// Log error clearly so user knows what happened
				// We intentionally don't fail the whole process just because one source failed.
				fmt.Fprintf(os.Stderr, "[!] Error fetching from %s: %v\n", s.Name(), err)
				return
			}

			// Map to findings
			findings, err := s.Map(raw, domain)
			if err != nil {
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(src)
	}

	wg.Wait()
	return allFindings, nil
}
