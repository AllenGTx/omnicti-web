package report

import (
	"domainscorer/internal/aggregation"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"time"
)

// GenerateHTMLReport creates a standalone HTML report file at the specified path.
// It wraps the Render function, handling file creation and cleanup.
func GenerateHTMLReport(result aggregation.Result, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	return Render(result, f)
}

// Render writes the complete HTML report to the provided writer (e.g., HTTP response or file).
// It compiles the embedded template and injects a set of helper functions for data formatting:
// - json: Marshals data to JSON for JS consumption.
// - scoreColor/severityColor: Returns Tailwind CSS classes based on risk levels.
// - formatTime: Formats Go time objects.
func Render(result aggregation.Result, w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.MarshalIndent(v, "", "  ")
			return template.JS(b)
		},
		"scoreColor": func(score float64) string {
			switch {
			case score >= 80:
				return "#ef4444" // Critical - Red
			case score >= 60:
				return "#f97316" // High - Orange
			case score >= 30:
				return "#eab308" // Medium - Yellow
			default:
				return "#3b82f6" // Low - Blue
			}
		},
		"severityColor": func(severity string) string {
			switch severity {
			case "critical":
				return "bg-red-500/20 text-red-500 border-red-500/30"
			case "high":
				return "bg-orange-500/20 text-orange-500 border-orange-500/30"
			case "medium":
				return "bg-yellow-500/20 text-yellow-500 border-yellow-500/30"
			case "low":
				return "bg-blue-500/20 text-blue-500 border-blue-500/30"
			default: // info
				return "bg-gray-500/20 text-gray-500 border-gray-500/30"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05 MST")
		},
		"toLower": func(s string) string {
			return strings.ToLower(s)
		},
	}).Parse(reportTemplate)

	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(w, result); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// reportTemplate is the self-contained HTML/CSS/JS template for the report.
// It includes:
// 1. A responsive UI using Tailwind CSS (via CDN).
// 2. A Score Gauge visualization.
// 3. The Aggregated AI Analysis section.
// 4. A sortable/filterable list of findings.
const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniCTI Risk Report: {{.Domain}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #e2e8f0; }
        .gauge-container { position: relative; width: 200px; height: 100px; overflow: hidden; margin: 0 auto; }
        .gauge-bg { position: absolute; top: 0; left: 0; width: 200px; height: 200px; border-radius: 50%; background: #1e293b; clip-path: polygon(0 0, 100% 0, 100% 50%, 0 50%); transform: rotate(180deg); }
        .gauge-fill { position: absolute; top: 0; left: 0; width: 200px; height: 200px; border-radius: 50%; clip-path: polygon(0 0, 100% 0, 100% 50%, 0 50%); transform-origin: center; transition: transform 1s ease-out; }
        .gauge-cover { position: absolute; top: 20px; left: 20px; width: 160px; height: 160px; background: #0f172a; border-radius: 50%; z-index: 10; }
        .gauge-value { position: absolute; bottom: 0; left: 0; width: 100%; text-align: center; font-size: 2.5rem; font-weight: 700; color: white; z-index: 20; }
        .gauge-label { position: absolute; bottom: -25px; left: 0; width: 100%; text-align: center; font-size: 0.875rem; color: #94a3b8; z-index: 20; }
        
        .finding-card { transition: all 0.2s; }
        .finding-card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); }
        
        pre { background: #1e293b; border-radius: 0.5rem; padding: 1rem; overflow-x: auto; font-size: 0.875rem; color: #a5b4fc; }
        
        details > summary { list-style: none; cursor: pointer; }
        details > summary::-webkit-details-marker { display: none; }
        
        .severity-badge { text-transform: uppercase; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; padding: 2px 8px; border-radius: 9999px; border: 1px solid; }

        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #64748b; }
    </style>
</head>
<body class="min-h-screen pb-10">

    <!-- Header -->
    <header class="bg-slate-900 border-b border-slate-800 sticky top-0 z-50 backdrop-blur-md bg-opacity-80">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <a href="/" class="flex items-center space-x-2 text-slate-400 hover:text-white transition-colors mr-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                    </svg>
                    <span class="text-sm font-medium">Back</span>
                </a>
                <div class="w-px h-6 bg-slate-700"></div>
                <svg class="w-8 h-8 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                <h1 class="text-xl font-bold tracking-tight">OmniCTI</h1>
            </div>
            <div class="text-sm text-slate-400">
                Target: <span class="text-white font-mono font-medium ml-1">{{.Domain}}</span>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Score Overview -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <!-- Main Score Card -->
            <div class="md:col-span-1 bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col items-center justify-center relative overflow-hidden">
                <div class="absolute inset-0 bg-gradient-to-br from-indigo-500/10 to-purple-500/10"></div>
                <h2 class="text-slate-400 text-sm font-medium uppercase tracking-wider mb-6 relative z-10">Overall Risk Score</h2>
                
                <div class="gauge-container relative z-10">
                    <div class="gauge-bg"></div>
                    <div class="gauge-fill" style="background-color: {{scoreColor .Score}}; transform: rotate(0deg);"></div>
                    <div class="gauge-cover"></div>
                    <div class="gauge-value">{{printf "%.1f" .Score}}</div>
                    <div class="gauge-label uppercase tracking-widest text-xs font-bold" style="color: {{scoreColor .Score}}">{{.Level}}</div>
                </div>
            </div>

            <!-- Stats Card -->
            <div class="md:col-span-2 bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col justify-between">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-slate-400 text-sm font-medium uppercase tracking-wider">Risk Distribution</h2>
                    <span class="text-xs text-slate-500">Total Findings: {{len .Findings}}</span>
                </div>
                
                <!-- Severity Bars -->
                <div class="space-y-4">
                   <!-- This logic ideally needs to be pre-calculated in Go or JS, but for now we construct simplified bars -->
                   <div id="stats-container" class="space-y-3">
                       <!-- Populated by JS -->
                   </div>
                </div>
            </div>
        </div>

		<!-- AI Analysis Section -->
		{{if .AIAnalysis}}
		<section class="mb-8">
			<div class="bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
				<div class="px-6 py-4 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
					<div class="flex items-center space-x-2">
						<svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
						<h2 class="font-semibold text-slate-200">AI Risk Assessment (Aggregated)</h2>
					</div>
					<div class="text-xs text-slate-500 border border-slate-700 rounded px-2 py-1">
						Score: {{printf "%.1f" .AIAnalysis.FinalScore}}/100
					</div>
				</div>
				<div class="p-6 space-y-6">
					
					{{if .AIAnalysis.GlobalSummary}}
					<div class="bg-indigo-900/20 rounded-lg p-5 border border-indigo-500/30 mb-6">
						<h3 class="text-sm font-bold text-indigo-400 uppercase tracking-wider mb-3 flex items-center">
							<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
							Executive Summary
						</h3>
						<p class="text-slate-300 leading-relaxed text-sm mb-4">{{.AIAnalysis.GlobalSummary}}</p>
						
						{{if .AIAnalysis.GlobalImpact}}
						<div class="mb-4">
							<h4 class="text-xs font-semibold text-red-400 uppercase tracking-wider mb-1">Global Impact</h4>
							<p class="text-slate-400 text-xs">{{.AIAnalysis.GlobalImpact}}</p>
						</div>
						{{end}}

						{{if .AIAnalysis.GlobalRemediation}}
						<div>
							<h4 class="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">Strategic Remediation</h4>
							<ul class="space-y-1">
								{{range .AIAnalysis.GlobalRemediation}}
								<li class="flex items-start space-x-2 text-xs text-slate-400">
									<span class="text-green-500">•</span>
									<span>{{.}}</span>
								</li>
								{{end}}
							</ul>
						</div>
						{{end}}
					</div>
					{{end}}

					<div class="border-t border-slate-700 my-4"></div>

					{{range .AIAnalysis.Providers}}
					<div class="border-b border-slate-700 pb-4 last:border-0 last:pb-0">
						<h3 class="text-sm font-medium text-indigo-400 uppercase tracking-wider mb-2">
							Provider: {{.Provider}} 
							<span class="text-slate-500 text-xs ml-2">(Contribution: {{printf "%.1f" .Contribution}}%)</span>
						</h3>
						
						{{if .Error}}
						<div class="text-red-400 text-sm">Error: {{.Error}}</div>
						{{else if .Analysis}}
						<div class="space-y-4">
							<p class="text-slate-300 leading-relaxed text-sm">{{.Analysis.AnalysisSummary}}</p>
							
							{{if .Analysis.PotentialImpact}}
							<div class="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
								<h4 class="text-xs font-semibold text-red-400 uppercase tracking-wider mb-1">Potential Impact</h4>
								<p class="text-slate-400 text-xs">{{.Analysis.PotentialImpact}}</p>
							</div>
							{{end}}

							{{if .Analysis.RemediationRoadmap}}
							<div>
								<h4 class="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1">Remediation</h4>
								<ul class="space-y-1">
									{{range .Analysis.RemediationRoadmap}}
									<li class="flex items-start space-x-2 text-xs text-slate-400">
										<span class="text-green-500">•</span>
										<span>{{.}}</span>
									</li>
									{{end}}
								</ul>
							</div>
							{{end}}
						</div>
						{{end}}
					</div>
					{{end}}

				</div>
			</div>
		</section>
		{{end}}

        <!-- Filters & Findings -->
        <section>
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-bold text-white">Detailed Findings</h2>
                <div class="flex space-x-2">
                    <button onclick="filterFindings('all')" class="px-3 py-1.5 text-xs font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition">All</button>
                    <button onclick="filterFindings('critical')" class="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-700 text-slate-300 hover:bg-slate-600 transition hover:text-white">Critical</button>
                    <button onclick="filterFindings('high')" class="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-700 text-slate-300 hover:bg-slate-600 transition hover:text-white">High</button>
                    <button onclick="filterFindings('medium')" class="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-700 text-slate-300 hover:bg-slate-600 transition hover:text-white">Medium</button>
                </div>
            </div>

            <div class="space-y-4" id="findings-list">
                {{range $i, $f := .Findings}}
                <details class="finding-card bg-slate-800 rounded-lg border border-slate-700 overflow-hidden group" data-severity="{{toLower $f.Severity}}"> <!-- Go template lowercase logic usually standard, using JS for filter -->
                    <summary class="px-6 py-4 flex items-center justify-between hover:bg-slate-750 cursor-pointer select-none">
                        <div class="flex items-center space-x-4">
                            <span class="severity-badge {{severityColor $f.Severity}} w-20 text-center">{{$f.Severity}}</span>
                            <div>
                                <h3 class="text-sm font-semibold text-white group-hover:text-indigo-400 transition">{{$f.Type}}</h3>
                                <div class="text-xs text-slate-400 mt-1 flex items-center space-x-2">
                                    <span>Source: {{$f.Source}}</span>
                                    <span>•</span>
                                    <span>Asset: {{$f.Asset}}</span>
                                    <span>•</span>
                                    <span>{{formatTime $f.ObservedAt}}</span>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-4">
                            <div class="text-right">
                                <div class="text-sm font-bold {{if ge $f.BaseScore 80.0}}text-red-400{{else if ge $f.BaseScore 60.0}}text-orange-400{{else}}text-slate-400{{end}}">
                                    Score: {{printf "%.1f" $f.BaseScore}}
                                </div>
                                {{if gt $f.Multiplier 1.0}}
                                <div class="text-xs text-purple-400">x{{$f.Multiplier}} Mult</div>
                                {{end}}
                            </div>
                            <svg class="w-5 h-5 text-slate-500 transform group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                        </div>
                    </summary>
                    
                    <div class="px-6 pb-6 pt-2 bg-slate-800/50 border-t border-slate-700/50">
                        <h4 class="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Evidence</h4>
                        <pre><code>{{json $f.Evidence}}</code></pre>
                    </div>
                </details>
                {{end}}
            </div>
        </section>

    </main>

    <script>
        // Data injected from Go for JS logic
        const findings = {{json .Findings}};

        // Stats Calculation
        const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        findings.forEach(f => {
            const s = f.Severity.toLowerCase();
            if (stats[s] !== undefined) stats[s]++;
            else stats.info++; // fallback
        });

        const total = findings.length;

        function renderStats() {
            const container = document.getElementById('stats-container');
            const max = Math.max(...Object.values(stats), 1); // Avoid div by zero

            const order = ['critical', 'high', 'medium', 'low', 'info'];
            const colors = {
                critical: 'bg-red-500',
                high: 'bg-orange-500',
                medium: 'bg-yellow-500',
                low: 'bg-blue-500',
                info: 'bg-gray-500'
            };

            order.forEach(sev => {
                if (stats[sev] === 0) return;
                
                const percent = (stats[sev] / total) * 100;
                
                const div = document.createElement('div');
                div.innerHTML = 
                    '<div class="flex items-center justify-between text-xs mb-1">' +
                        '<span class="capitalize text-slate-300 font-medium">' + sev + '</span>' +
                        '<span class="text-slate-400">' + stats[sev] + ' (' + Math.round(percent) + '%)</span>' +
                    '</div>' +
                    '<div class="w-full bg-slate-700 rounded-full h-2">' +
                        '<div class="' + colors[sev] + ' h-2 rounded-full" style="width: ' + percent + '%"></div>' +
                    '</div>';
                container.appendChild(div);
            });
        }

        // Filtering Logic
        function filterFindings(severity) {
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                // ToLower logic in Go template might fail, so we rely on data attribute if set correctly
                // Ideally we fix the template to output lowercase class or data attr
                const cardSev = card.getAttribute('data-severity'); 
                if (severity === 'all' || cardSev === severity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        // Initialize Gauge Rotation (Simple CSS trick)
        // Note: The inline style in HTML handles the static rotation. 
        // We can add animation here if desired.
        
        document.addEventListener('DOMContentLoaded', () => {
             renderStats();
             
             // Fix gauge rotation
             const score = {{.Score}};
             const rotation = (score / 100) * 180;
             document.querySelector('.gauge-fill').style.transform = "rotate(" + rotation + "deg)";
        });

    </script>
</body>
</html>
`
