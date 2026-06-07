package health

import "testing"

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "git+https://github.com/expressjs/express.git",
			want:  "https://github.com/expressjs/express",
		},
		{
			input: "git://github.com/lodash/lodash.git",
			want:  "https://github.com/lodash/lodash",
		},
		{
			input: "https://github.com/facebook/react",
			want:  "https://github.com/facebook/react",
		},
		{
			input: "git@github.com:vuejs/vue.git",
			want:  "https://github.com/vuejs/vue",
		},
		{
			input: "https://github.com/pallets/flask/tree/main",
			want:  "https://github.com/pallets/flask",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeGitURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeGitURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
