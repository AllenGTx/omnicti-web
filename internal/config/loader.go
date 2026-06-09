package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// ScoringConfig holds all scoring constants
type ScoringConfig struct {
	Severity      map[string]float64  `yaml:"severity"`
	Reliability   ReliabilityConfig   `yaml:"reliability"`
	BusinessLogic BusinessLogicConfig `yaml:"business_logic"`
	AI            AIConfig            `yaml:"ai"`
}

type ReliabilityConfig struct {
	Sources map[string]float64 `yaml:"sources"`
	Default float64            `yaml:"default"`
}

type BusinessLogicConfig struct {
	Rules             []BusinessLogicRule `yaml:"rules"`
	DefaultMultiplier float64             `yaml:"default_multiplier"`
}

type BusinessLogicRule struct {
	Name       string   `yaml:"name"`
	Keywords   []string `yaml:"keywords"`
	Multiplier float64  `yaml:"multiplier"`
}

type AIConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"` // gemini, openai, groq
	Model    string `yaml:"model"`
	APIKey   string `yaml:"-"` // Load from Env
}

var CurrentScoringConfig ScoringConfig

// Load reads the .env file and loads it into the environment.
// It does not fail if the file is missing, as env vars might be set otherwise.
func Load() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found or error loading it, using system environment variables.")
	}
}

// LoadScoring loads the scoring configuration from a yaml file
func LoadScoring(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, &CurrentScoringConfig)
	if err != nil {
		return err
	}

	return nil
}
