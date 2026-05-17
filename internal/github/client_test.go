package github

import "testing"

func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "https URL",
			url:       "https://github.com/expressjs/express",
			wantOwner: "expressjs",
			wantRepo:  "express",
		},
		{
			name:      "https URL with .git",
			url:       "https://github.com/expressjs/express.git",
			wantOwner: "expressjs",
			wantRepo:  "express",
		},
		{
			name:      "https URL with trailing slash",
			url:       "https://github.com/expressjs/express/",
			wantOwner: "expressjs",
			wantRepo:  "express",
		},
		{
			name:      "SSH URL",
			url:       "git@github.com:expressjs/express.git",
			wantOwner: "expressjs",
			wantRepo:  "express",
		},
		{
			name:      "www URL",
			url:       "https://www.github.com/lodash/lodash",
			wantOwner: "lodash",
			wantRepo:  "lodash",
		},
		{
			name:    "non-GitHub URL",
			url:     "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			url:     "not-a-url",
			wantErr: true,
		},
		{
			name:    "missing repo",
			url:     "https://github.com/owner",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := ParseRepoURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRepoURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if owner != tt.wantOwner {
					t.Errorf("ParseRepoURL() owner = %v, want %v", owner, tt.wantOwner)
				}
				if repo != tt.wantRepo {
					t.Errorf("ParseRepoURL() repo = %v, want %v", repo, tt.wantRepo)
				}
			}
		})
	}
}

func TestNewClient(t *testing.T) {
        t.Setenv("GITHUB_TOKEN", "")
	
        client := NewClient("")
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.HasToken() {
		t.Error("HasToken() should be false for empty token")
	}

	clientWithToken := NewClient("test-token")
	if !clientWithToken.HasToken() {
		t.Error("HasToken() should be true with token")
	}
}

func TestCalculateRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		metrics  HealthMetrics
		wantRisk string
	}{
		{
			name: "healthy repo",
			metrics: HealthMetrics{
				CommitFrequency: "active",
				Contributors:    50,
				RepoInfo:        RepoInfo{Stars: 1000},
			},
			wantRisk: "low",
		},
		{
			name: "abandoned single maintainer",
			metrics: HealthMetrics{
				CommitFrequency: "abandoned",
				Contributors:    1,
				RepoInfo:        RepoInfo{Stars: 5},
			},
			wantRisk: "high",
		},
		{
			name: "moderate activity few contributors",
			metrics: HealthMetrics{
				CommitFrequency: "moderate",
				Contributors:    2,
				RepoInfo:        RepoInfo{Stars: 100},
			},
			wantRisk: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateRiskLevel(&tt.metrics)
			if got != tt.wantRisk {
				t.Errorf("calculateRiskLevel() = %v, want %v", got, tt.wantRisk)
			}
		})
	}
}
