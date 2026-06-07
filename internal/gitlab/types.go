package gitlab

import "time"

// TreeEntry represents a file or directory in the GitLab repository tree.
type TreeEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // "blob" or "tree"
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// FileContent holds raw file content fetched from the GitLab API.
type FileContent struct {
	Content []byte
	Path    string
}

// RateLimit tracks the current API rate limit state.
type RateLimit struct {
	Remaining int
	Limit     int
	ResetAt   time.Time
}

// ProjectInfo holds basic repository metadata.
type ProjectInfo struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
}
