package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const configFilename = "config.json"

// Config holds SBOMber configuration
type Config struct {
	GitHubToken string `json:"github_token,omitempty"`
}

// Load reads config from ~/.sbomber/config.json
func Load() (*Config, error) {
	path, err := getConfigPath()
	if err != nil {
		return &Config{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &Config{}, nil
	}

	return &cfg, nil
}

// Save writes config to ~/.sbomber/config.json
func Save(cfg *Config) error {
	path, err := getConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// GetGitHubToken returns token from config or env var
func GetGitHubToken() string {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}

	cfg, err := Load()
	if err != nil {
		return ""
	}

	return cfg.GitHubToken
}

// SaveGitHubToken saves the token to config file
func SaveGitHubToken(token string) error {
	cfg, err := Load()
	if err != nil {
		cfg = &Config{}
	}

	cfg.GitHubToken = token
	return Save(cfg)
}

// HasGitHubToken checks if a token is available
func HasGitHubToken() bool {
	return GetGitHubToken() != ""
}

func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".sbomber", configFilename), nil
}
