package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D4FF")).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Italic(true)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88"))

	unselectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	accentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D4FF"))

	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88"))

	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D4FF")).
			MarginLeft(2)

	menuBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#444444")).
			Padding(1, 2).
			MarginLeft(2)

	inputStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))
)

// View states
type viewState int

const (
	viewMenu viewState = iota
	viewFormat
	viewVulnScan
	viewPathInput
	viewScanning
	viewDone
)

// Menu item
type menuItem struct {
	label string
	desc  string
}

// TUI model
type model struct {
	state        viewState
	cursor       int
	items        []menuItem
	formats      []menuItem
	vulnOptions  []menuItem
	selected     string
	scanPath     string
	scanFormat   string
	includeVulns bool
	pathInput    string
	scanOutput   string
	quitting     bool
}

func newModel() model {
	return model{
		state: viewMenu,
		items: []menuItem{
			{label: "Scan current folder", desc: "Scan repos in the current directory"},
			{label: "Scan custom folder", desc: "Choose a folder to scan"},
			{label: "Version", desc: "Show SBOMber version"},
			{label: "Help", desc: "Show usage information"},
			{label: "Exit", desc: "Quit SBOMber"},
		},
		formats: []menuItem{
			{label: "CycloneDX", desc: "recommended"},
			{label: "SPDX", desc: "alternative standard"},
			{label: "Both", desc: "generate both formats"},
		},
		vulnOptions: []menuItem{
			{label: "Yes", desc: "scan for CVEs using Grype"},
			{label: "No", desc: "skip vulnerability scanning"},
		},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case viewMenu:
			return m.updateMenu(msg)
		case viewFormat:
			return m.updateFormat(msg)
		case viewVulnScan:
			return m.updateVulnScan(msg)
		case viewPathInput:
			return m.updatePathInput(msg)
		case viewScanning, viewDone:
			return m.updatePost(msg)
		}
	}
	return m, nil
}

func (m model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0: // Scan current folder
			m.scanPath = "."
			m.state = viewFormat
			m.cursor = 0
		case 1: // Scan custom folder
			m.state = viewPathInput
			m.pathInput = ""
		case 2: // Version
			m.selected = "version"
			m.state = viewDone
		case 3: // Help
			m.selected = "help"
			m.state = viewDone
		case 4: // Exit
			m.quitting = true
			return m, tea.Quit
		}
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateFormat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.formats)-1 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			m.scanFormat = formatCycloneDX
		case 1:
			m.scanFormat = formatSPDX
		case 2:
			m.scanFormat = formatBoth
		}
		m.state = viewVulnScan
		m.cursor = 0
	case "esc":
		m.state = viewMenu
		m.cursor = 0
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateVulnScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.vulnOptions)-1 {
			m.cursor++
		}
	case "enter":
		m.includeVulns = m.cursor == 0
		m.selected = "scan"
		m.state = viewScanning
		return m, tea.Quit
	case "esc":
		m.state = viewFormat
		m.cursor = 0
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updatePathInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		if m.pathInput == "" {
			m.pathInput = "."
		}
		m.scanPath = m.pathInput
		m.state = viewFormat
		m.cursor = 0
	case tea.KeyBackspace:
		if len(m.pathInput) > 0 {
			m.pathInput = m.pathInput[:len(m.pathInput)-1]
		}
	case tea.KeyEsc:
		m.state = viewMenu
		m.cursor = 0
	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyTab:
		m.pathInput = expandPathWithTab(m.pathInput)
	case tea.KeySpace:
		m.pathInput += " "
	case tea.KeyRunes:
		m.pathInput += string(msg.Runes)
	}
	return m, nil
}

func (m model) updatePost(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", "q", "ctrl+c":
		if m.selected == "version" || m.selected == "help" {
			m.state = viewMenu
			m.cursor = 0
			m.selected = ""
			return m, nil
		}
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(renderBanner())
	b.WriteString("\n")

	switch m.state {
	case viewMenu:
		b.WriteString(m.renderMenu())
	case viewFormat:
		b.WriteString(m.renderFormatSelect())
	case viewVulnScan:
		b.WriteString(m.renderVulnScan())
	case viewPathInput:
		b.WriteString(m.renderPathInput())
	case viewDone:
		b.WriteString(m.renderDone())
	}

	return b.String()
}

func renderBanner() string {
	banner := `  ____  ____   ___  __  __ ____
 / ___|| __ ) / _ \|  \/  | __ )  ___ _ __
 \___ \|  _ \| | | | |\/| |  _ \ / _ \ '__|
  ___) | |_) | |_| | |  | | |_) |  __/ |
 |____/|____/ \___/|_|  |_|____/ \___|_|`

	return bannerStyle.Render(banner) + "\n" +
		lipgloss.NewStyle().MarginLeft(2).Foreground(lipgloss.Color("#666666")).Render("  v"+version) + "\n\n" +
		lipgloss.NewStyle().MarginLeft(2).Foreground(lipgloss.Color("#888888")).Render("  A lightweight CLI for scanning local repositories and generating SBOMs.") + "\n\n"
}

func (m model) renderMenu() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  SELECT AN OPTION")
	b.WriteString(header + "\n\n")

	for i, item := range m.items {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  q quit") + "\n")

	return b.String()
}

func (m model) renderFormatSelect() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  SBOM EXPORT FORMAT")
	b.WriteString(header + "\n\n")

	scanLabel := accentStyle.Render(m.scanPath)
	b.WriteString(dimStyle.MarginLeft(2).Render("  Scanning: ") + scanLabel + "\n\n")

	for i, item := range m.formats {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderVulnScan() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  VULNERABILITY SCANNING")
	b.WriteString(header + "\n\n")

	scanLabel := accentStyle.Render(m.scanPath)
	formatLabel := accentStyle.Render(m.scanFormat)
	b.WriteString(dimStyle.MarginLeft(2).Render("  Scanning: ") + scanLabel + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Format: ") + formatLabel + "\n\n")

	b.WriteString(dimStyle.MarginLeft(2).Render("  Include vulnerability scan with Grype?") + "\n\n")

	for i, item := range m.vulnOptions {
		cursor := "  "
		label := unselectedStyle.Render(item.label)
		desc := dimStyle.Render(item.desc)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(item.label)
			bullet = successStyle.Render("●")
			desc = subtitleStyle.Render(item.desc)
		}

		line := fmt.Sprintf("  %s %s %s  %s", cursor, bullet, label, desc)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  ↑/↓ navigate  enter select  esc back") + "\n")

	return b.String()
}

func (m model) renderPathInput() string {
	var b strings.Builder

	header := titleStyle.MarginLeft(2).Render("  ENTER FOLDER PATH")
	b.WriteString(header + "\n\n")

	prompt := inputStyle.Render("  Path: ")
	cursor := accentStyle.Render("█")
	input := accentStyle.Render(m.pathInput)

	b.WriteString("  " + prompt + input + cursor + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  enter confirm  esc back") + "\n")

	return b.String()
}

func (m model) renderDone() string {
	var b strings.Builder

	switch m.selected {
	case "version":
		ver := accentStyle.Render("SBOMber") + " " + dimStyle.Render("v"+version)
		b.WriteString("  " + ver + "\n\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	case "help":
		b.WriteString(renderHelp())
		b.WriteString("\n")
		b.WriteString(dimStyle.MarginLeft(2).Render("  Press Enter to return to menu") + "\n")
	}

	return b.String()
}

func renderHelp() string {
	var b strings.Builder

	b.WriteString(titleStyle.MarginLeft(2).Render("  USAGE") + "\n\n")
	b.WriteString(fmt.Sprintf("  %s                                     %s\n", accentStyle.Render("  sbomber"), dimStyle.Render("Interactive mode")))
	b.WriteString(fmt.Sprintf("  %s [path] [flags]                 %s\n", accentStyle.Render("  sbomber scan"), dimStyle.Render("Scan repositories")))
	b.WriteString(fmt.Sprintf("  %s                             %s\n\n", accentStyle.Render("  sbomber version"), dimStyle.Render("Show version")))

	b.WriteString(titleStyle.MarginLeft(2).Render("  FLAGS") + "\n\n")
	b.WriteString(fmt.Sprintf("  %s   cyclonedx | spdx | both          %s\n", accentStyle.Render("  --format"), dimStyle.Render("(default: cyclonedx)")))
	b.WriteString(fmt.Sprintf("  %s             %s\n\n", accentStyle.Render("  --include-vulnerabilities"), dimStyle.Render("scan vulnerabilities with Grype")))

	b.WriteString(titleStyle.MarginLeft(2).Render("  VULNERABILITY SCANNING") + "\n\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  SBOMber uses Grype when vulnerability scanning is enabled.") + "\n")
	b.WriteString(dimStyle.MarginLeft(2).Render("  Install Grype from https://github.com/anchore/grype.") + "\n")

	return b.String()
}

// runTUI launches the bubbletea interactive TUI and returns the user's choice.
func runTUI() (action string, scanPath string, scanFormat string, includeVulns bool) {
	m := newModel()

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return "exit", "", "", false
	}

	final := finalModel.(model)
	if final.quitting && final.selected == "" {
		return "exit", "", "", false
	}

	// Clear screen after TUI exits for clean transition
	fmt.Print("\033[H\033[2J")

	return final.selected, final.scanPath, final.scanFormat, final.includeVulns
}

// resultsModel for showing scan results with actions
type resultsModel struct {
	content    string
	outputPath string
	cursor     int
	actions    []string
	quitting   bool
	openFolder bool
}

func newResultsModel(content, outputPath string) resultsModel {
	return resultsModel{
		content:    content,
		outputPath: outputPath,
		cursor:     0,
		actions:    []string{"Back to menu", "Open output folder", "Quit"},
	}
}

func (m resultsModel) Init() tea.Cmd {
	return nil
}

func (m resultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.actions)-1 {
				m.cursor++
			}
		case "enter":
			switch m.cursor {
			case 0: // Back to menu
				m.quitting = true
				return m, tea.Quit
			case 1: // Open folder - open and stay
				if m.outputPath != "" {
					openFolder(m.outputPath)
				}
				return m, nil // Stay on results screen
			case 2: // Quit
				m.quitting = true
				m.cursor = 2 // Mark as quit
				return m, tea.Quit
			}
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m resultsModel) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(renderBanner())

	// Results header
	headerBox := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FF88")).
		MarginLeft(4).
		MarginBottom(1)
	b.WriteString(headerBox.Render("SCAN COMPLETE") + "\n\n")

	// Content - no color styling so it works on light and dark terminals
	// Render each line with just margin
	for _, line := range strings.Split(m.content, "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString("\n")

	// Output location
	if m.outputPath != "" {
		pathStyle := lipgloss.NewStyle().
			MarginLeft(4).
			Foreground(lipgloss.Color("#888888"))
		pathValue := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00D4FF"))
		b.WriteString(pathStyle.Render("Output: ") + pathValue.Render(m.outputPath) + "\n\n")
	}

	// Divider
	divider := lipgloss.NewStyle().
		MarginLeft(4).
		Foreground(lipgloss.Color("#444444"))
	b.WriteString(divider.Render("─────────────────────────────────────────") + "\n\n")

	// Actions
	actionHeader := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00D4FF")).
		MarginLeft(4)
	b.WriteString(actionHeader.Render("WHAT'S NEXT?") + "\n\n")

	for i, action := range m.actions {
		cursor := "  "
		label := unselectedStyle.Render(action)
		bullet := dimStyle.Render("○")

		if m.cursor == i {
			cursor = selectedStyle.Render("▸ ")
			label = selectedStyle.Render(action)
			bullet = successStyle.Render("●")
		}

		line := fmt.Sprintf("  %s %s %s", cursor, bullet, label)
		b.WriteString(lipgloss.NewStyle().MarginLeft(2).Render(line) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.MarginLeft(4).Render("↑/↓ navigate  enter select") + "\n")

	return b.String()
}

// showResultsScreen displays scan results in a styled TUI view
func showResultsScreen(content, outputPath string) bool {
	m := newResultsModel(content, outputPath)
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, _ := p.Run()
	final := finalModel.(resultsModel)

	// Return true if user wants to quit entirely (cursor == 2)
	return final.cursor == 2
}

// openFolder opens the folder in the system file manager
func openFolder(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

// expandPathWithTab provides basic tab completion for paths
func expandPathWithTab(input string) string {
	if input == "" {
		return input
	}

	// Expand ~ to home directory
	path := input
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}

	// Get directory and prefix
	dir := filepath.Dir(path)
	prefix := filepath.Base(path)

	// If path ends with /, list contents of that directory
	if strings.HasSuffix(input, "/") || strings.HasSuffix(input, string(filepath.Separator)) {
		dir = path
		prefix = ""
	}

	// Read directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return input
	}

	// Find matching entries
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			fullPath := filepath.Join(dir, name)
			if entry.IsDir() {
				fullPath += string(filepath.Separator)
			}
			matches = append(matches, fullPath)
		}
	}

	// Return first match or original input
	if len(matches) == 1 {
		// Convert back to use ~ if it was used
		if strings.HasPrefix(input, "~") {
			home, _ := os.UserHomeDir()
			if strings.HasPrefix(matches[0], home) {
				return "~" + strings.TrimPrefix(matches[0], home)
			}
		}
		return matches[0]
	}

	// Find common prefix among matches
	if len(matches) > 1 {
		common := matches[0]
		for _, m := range matches[1:] {
			for i := 0; i < len(common) && i < len(m); i++ {
				if common[i] != m[i] {
					common = common[:i]
					break
				}
			}
			if len(m) < len(common) {
				common = common[:len(m)]
			}
		}
		if len(common) > len(path) {
			if strings.HasPrefix(input, "~") {
				home, _ := os.UserHomeDir()
				if strings.HasPrefix(common, home) {
					return "~" + strings.TrimPrefix(common, home)
				}
			}
			return common
		}
	}

	return input
}
