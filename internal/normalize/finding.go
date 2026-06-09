package normalize

import "time"

type Finding struct {
	Source     string         // leakix, shodan, fofa
	Type       string         // misconfiguration, vulnerability, reputation
	Severity   string         // critical, high, medium, low, info
	BaseScore  float64        // nilai sebelum decay
	Multiplier float64        // business logic impact multiplier (1.0 - 2.0)
	ObservedAt time.Time      // kapan terakhir terlihat
	Asset      string         // ip / domain
	Evidence   map[string]any // raw proof
}
