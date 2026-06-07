package github

import "time"

// RepoInfo contains basic repository metadata.
type RepoInfo struct {
	Owner       string
	Name        string
	FullName    string
	Description string
	Stars       int
	Forks       int
	OpenIssues  int
	License     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	PushedAt    time.Time
}

// TreeEntry represents a file or directory in a repository tree.
type TreeEntry struct {
	Path string
	Type string // "blob" or "tree"
	SHA  string
	Size int
}

// FileContent holds the decoded content of a file.
type FileContent struct {
	Path    string
	Content []byte
	SHA     string
}

// ContributorStats holds contributor information for a repository.
type ContributorStats struct {
	TotalContributors int
	TopContributors   []Contributor
}

// Contributor represents a single contributor.
type Contributor struct {
	Login         string
	Contributions int
}

// HealthMetrics aggregates supply chain health signals.
type HealthMetrics struct {
	RepoInfo
	Contributors    int
	LastCommitDate  time.Time
	CommitFrequency string // "active", "moderate", "inactive", "abandoned"
	RiskLevel       string // "low", "medium", "high"
}

// RateLimit holds GitHub API rate limit info.
type RateLimit struct {
	Limit     int
	Remaining int
	Reset     time.Time
}

// apiRepoResponse maps the GitHub API response for a repository.
type apiRepoResponse struct {
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Stars       int    `json:"stargazers_count"`
	Forks       int    `json:"forks_count"`
	OpenIssues  int    `json:"open_issues_count"`
	License     *struct {
		Name string `json:"name"`
	} `json:"license"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	PushedAt  string `json:"pushed_at"`
}

// apiTreeResponse maps the GitHub API response for repository tree.
type apiTreeResponse struct {
	SHA  string `json:"sha"`
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int    `json:"size"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

// apiContentResponse maps the GitHub API response for file content.
type apiContentResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	SHA      string `json:"sha"`
	Path     string `json:"path"`
}

// apiContributorResponse maps the GitHub API response for contributors.
type apiContributorResponse struct {
	Login         string `json:"login"`
	Contributions int    `json:"contributions"`
}
