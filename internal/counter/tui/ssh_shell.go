// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/crypto/ssh"
)

type SSHState struct {
	KeyName        string
	KeyValue       string
	KeyType        string
	KeyFingerprint string
	PivotTime      time.Time
	Scope          string
	TempDir        string
	Results        []SSHTrialResult
}

func (m *Model) updateSSHState(result PivotResultMsg) bool {
	replaced := false
	if m.sshState != nil && m.sshState.TempDir != "" && m.sshState.KeyValue != "" && m.sshState.KeyValue != result.KeyValue {
		_ = os.RemoveAll(m.sshState.TempDir)
		replaced = true
	}

	if m.sshState == nil {
		m.sshState = &SSHState{}
	}

	m.sshState.KeyName = result.KeyName
	m.sshState.KeyValue = result.KeyValue
	m.sshState.KeyType = result.KeyType
	m.sshState.KeyFingerprint = result.KeyFP
	m.sshState.PivotTime = time.Now()
	m.sshState.Scope = result.SSHScope
	m.sshState.Results = append([]SSHTrialResult(nil), result.SSHResults...)
	if replaced {
		m.sshState.TempDir = ""
	}
	return replaced
}

func sshSuccessfulResults(results []SSHTrialResult) []SSHTrialResult {
	var successful []SSHTrialResult
	for _, result := range results {
		if result.Success {
			successful = append(successful, result)
		}
	}
	return successful
}

func (m Model) executeSSHCommand(args []string) (tea.Model, tea.Cmd) {
	if len(args) == 0 {
		m.showSSHStatus()
		return m, nil
	}

	switch args[0] {
	case "status":
		m.showSSHStatus()
		return m, nil
	case "shell":
		return m.executeSSHShell()
	default:
		m.AddOutput("error", fmt.Sprintf("Unknown ssh subcommand: %s", args[0]))
		m.AddOutput("info", "Try: ssh status | ssh shell | pivot ssh | pivot ssh org:<owner> | pivot ssh repo:<owner/repo>")
		return m, nil
	}
}

func (m *Model) cleanupSSHSession() {
	if m.sshState == nil {
		return
	}
	if m.sshState.TempDir != "" {
		os.RemoveAll(m.sshState.TempDir)
		m.sshState.TempDir = ""
	}
}

func (m *Model) showSSHStatus() {
	if m.sshState == nil {
		m.activityLog.Add(IconWarning, "No active SSH session. Run 'pivot ssh' first.")
		return
	}

	ss := m.sshState
	m.activityLog.Add(IconInfo, fmt.Sprintf("SSH Session: %s", ss.KeyName))
	if ss.KeyType != "" || ss.KeyFingerprint != "" {
		var details []string
		if ss.KeyType != "" {
			details = append(details, ss.KeyType)
		}
		if ss.KeyFingerprint != "" {
			details = append(details, ss.KeyFingerprint)
		}
		m.activityLog.Add(IconInfo, "  Key: "+strings.Join(details, " · "))
	}
	if !ss.PivotTime.IsZero() {
		m.activityLog.Add(IconInfo, fmt.Sprintf("  Pivoted: %s ago", time.Since(ss.PivotTime).Truncate(time.Second)))
	}
	if ss.Scope != "" {
		m.activityLog.Add(IconInfo, "  Scope: "+ss.Scope)
	}

	successful := sshSuccessfulResults(ss.Results)
	if len(successful) == 0 {
		m.activityLog.Add(IconWarning, "  Confirmed repos: none yet")
		if ss.Scope != "" {
			m.activityLog.Add(IconInfo, "  Probe next: pivot ssh "+ss.Scope)
			if strings.HasPrefix(ss.Scope, "repo:") {
				if owner := repoOwner(strings.TrimPrefix(ss.Scope, "repo:")); owner != "" {
					m.activityLog.Add(IconInfo, "  Broaden: pivot ssh org:"+owner)
				}
			}
		} else {
			m.activityLog.Add(IconInfo, "  Probe next: pivot ssh org:<owner>")
		}
	} else {
		writes := 0
		for _, result := range successful {
			if result.Permission == "write" {
				writes++
			}
		}
		m.activityLog.Add(IconInfo, fmt.Sprintf("  Confirmed repos: %d (%d write)", len(successful), writes))
		for i, result := range successful {
			if i >= 10 {
				m.activityLog.Add(IconInfo, fmt.Sprintf("  ... and %d more", len(successful)-10))
				break
			}
			m.activityLog.Add(IconInfo, fmt.Sprintf("    %s (%s)", result.Repo, result.Permission))
		}
	}

	if ss.TempDir != "" {
		m.activityLog.Add(IconInfo, "  ssh shell  → ready")
	} else {
		m.activityLog.Add(IconInfo, "  ssh shell  → not started")
	}
	m.activityLog.Add(IconInfo, "  helpers    → sm-context | sm-clone owner/repo | vim | nano")
}

func (m Model) executeSSHShell() (tea.Model, tea.Cmd) {
	ss := m.sshState
	if ss == nil {
		m.AddOutput("error", "No active SSH session. Run 'pivot ssh' first.")
		return m, nil
	}
	if strings.TrimSpace(ss.KeyValue) == "" {
		m.AddOutput("error", "SSH session has no usable private key. Re-run 'pivot ssh'.")
		return m, nil
	}

	if ss.TempDir != "" {
		if _, err := os.Stat(ss.TempDir); err == nil {
			m.AddOutput("info", fmt.Sprintf("Resuming ssh shell with %s (session age: %s)", ss.KeyName, time.Since(ss.PivotTime).Truncate(time.Second)))
			m.addSSHShellGuidance(ss)
			return m, m.spawnSSHShell(ss)
		}
		ss.TempDir = ""
	}

	sessionsDir := filepath.Join(smokedmeatDir(), "ssh-shell", "sessions")
	if err := os.MkdirAll(sessionsDir, 0o700); err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to create ssh shell dir: %v", err))
		return m, nil
	}

	tmpDir, err := os.MkdirTemp(sessionsDir, "sm-ssh-*")
	if err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to create temp dir: %v", err))
		return m, nil
	}
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to set permissions on temp dir: %v", err))
		_ = os.RemoveAll(tmpDir)
		return m, nil
	}
	ss.TempDir = tmpDir

	if err := setupSSHShellHome(ss); err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to prepare ssh shell: %v", err))
		_ = os.RemoveAll(tmpDir)
		ss.TempDir = ""
		return m, nil
	}

	image := cloudShellImageRefFn()
	if !embeddedCloudShellAvailableFn() && cloudShellNeedsLocalImage() && !dockerHasImageFn(image) {
		m.AddOutput("error", fmt.Sprintf("SSH shell requires the Docker image '%s'. Build it with 'make cloud-shell-image'.", image))
		_ = os.RemoveAll(tmpDir)
		ss.TempDir = ""
		return m, nil
	}

	m.AddOutput("info", fmt.Sprintf("Entering ssh shell with %s (Ctrl+D or 'exit' to return)", ss.KeyName))
	m.addSSHShellGuidance(ss)
	return m, m.spawnSSHShell(ss)
}

func setupSSHShellHome(ss *SSHState) error {
	sshDir := filepath.Join(ss.TempDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}

	keyPath := filepath.Join(sshDir, "id_smokedmeat")
	if err := os.WriteFile(keyPath, []byte(ss.KeyValue), 0o600); err != nil {
		return err
	}

	var knownHosts bytes.Buffer
	for _, key := range githubSSHHostKeys {
		knownHosts.WriteString("github.com ")
		knownHosts.Write(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)))
		knownHosts.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), knownHosts.Bytes(), 0o600); err != nil {
		return err
	}

	config := strings.Join([]string{
		"Host github.com",
		"  HostName github.com",
		"  User git",
		"  IdentitiesOnly yes",
		"  StrictHostKeyChecking yes",
		"  LogLevel ERROR",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(config), 0o600); err != nil {
		return err
	}

	gitConfig := strings.Join([]string{
		"[user]",
		"\tname = SmokedMeat",
		"\temail = smokedmeat@example.com",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(ss.TempDir, ".gitconfig"), []byte(gitConfig), 0o600); err != nil {
		return err
	}
	return writeSSHShellHelpers(ss)
}

func sshShellEnv(ss *SSHState, shellHome string) []string {
	identityPath := filepath.Join(shellHome, ".ssh", "id_smokedmeat")
	knownHostsPath := filepath.Join(shellHome, ".ssh", "known_hosts")
	sshCommand := strings.Join([]string{
		"ssh",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + identityPath,
		"-o", "UserKnownHostsFile=" + knownHostsPath,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "LogLevel=ERROR",
	}, " ")
	basePath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	helperPath := filepath.Join(shellHome, "bin")
	env := []string{
		"HOME=" + shellHome,
		"SM_SHELL_HOME=" + shellHome,
		"SM_PROVIDER=ssh",
		"SM_METHOD=git",
		"PATH=" + helperPath + ":" + basePath,
		"GIT_CONFIG_GLOBAL=" + filepath.Join(shellHome, ".gitconfig"),
		"GIT_SSH_COMMAND=" + sshCommand,
		"SM_SSH_IDENTITY=" + identityPath,
		"SM_SSH_KNOWN_HOSTS=" + knownHostsPath,
	}
	if ss.KeyFingerprint != "" {
		env = append(env, "SM_SSH_FINGERPRINT="+ss.KeyFingerprint)
	}
	if ss.Scope != "" {
		env = append(env, "SM_SSH_SCOPE="+ss.Scope)
	}
	return env
}

func (m *Model) addSSHShellGuidance(ss *SSHState) {
	m.AddOutput("info", "  Git identity ready: SmokedMeat <smokedmeat@example.com>")
	writeRepos, readRepos := sshShellRepoBuckets(ss.Results)
	if len(writeRepos) > 0 {
		m.AddOutput("success", fmt.Sprintf("  Confirmed write repos: %d", len(writeRepos)))
		for i, repo := range writeRepos {
			if i >= 5 {
				m.AddOutput("info", fmt.Sprintf("  ... and %d more", len(writeRepos)-5))
				break
			}
			m.AddOutput("info", "    "+repo)
		}
	}
	if len(readRepos) > 0 {
		m.AddOutput("info", fmt.Sprintf("  Confirmed read-only repos: %d", len(readRepos)))
	}
	m.AddOutput("info", "  In shell: sm-context | sm-clone owner/repo | vim | nano")
}

func sshShellRepoBuckets(results []SSHTrialResult) (writeRepos, readRepos []string) {
	for _, result := range results {
		if !result.Success || result.Repo == "" {
			continue
		}
		if result.Permission == "write" {
			writeRepos = append(writeRepos, result.Repo)
			continue
		}
		readRepos = append(readRepos, result.Repo)
	}
	writeRepos = dedupeStrings(writeRepos)
	readRepos = dedupeStrings(readRepos)
	return writeRepos, readRepos
}

func writeSSHShellHelpers(ss *SSHState) error {
	writeRepos, readRepos := sshShellRepoBuckets(ss.Results)

	if err := os.WriteFile(filepath.Join(ss.TempDir, ".sm-write-repos"), []byte(strings.Join(writeRepos, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ss.TempDir, ".sm-read-repos"), []byte(strings.Join(readRepos, "\n")+"\n"), 0o600); err != nil {
		return err
	}

	binDir := filepath.Join(ss.TempDir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return err
	}

	contextScript := strings.Join([]string{
		"#!/usr/bin/env sh",
		"set -eu",
		"echo \"SSH shell ready\"",
		"echo \"Scope: ${SM_SSH_SCOPE:-all discovered repos}\"",
		"echo \"Fingerprint: ${SM_SSH_FINGERPRINT:-unknown}\"",
		"echo \"Git identity: $(git config user.name) <$(git config user.email)>\"",
		"if [ -s \"$HOME/.sm-write-repos\" ]; then",
		"  echo",
		"  echo \"Write repos:\"",
		"  sed 's/^/  - /' \"$HOME/.sm-write-repos\"",
		"fi",
		"if [ -s \"$HOME/.sm-read-repos\" ]; then",
		"  echo",
		"  echo \"Read-only repos:\"",
		"  sed 's/^/  - /' \"$HOME/.sm-read-repos\"",
		"fi",
		"if [ ! -s \"$HOME/.sm-write-repos\" ] && [ ! -s \"$HOME/.sm-read-repos\" ]; then",
		"  echo",
		"  echo \"No confirmed repo access yet\"",
		"fi",
		"echo",
		"echo \"Clone helper: sm-clone owner/repo\"",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(binDir, "sm-context"), []byte(contextScript), 0o700); err != nil {
		return err
	}

	cloneScript := strings.Join([]string{
		"#!/usr/bin/env sh",
		"set -eu",
		"if [ $# -ne 1 ]; then",
		"  echo \"usage: sm-clone owner/repo\" >&2",
		"  exit 1",
		"fi",
		"case \"$1\" in",
		"  */*) ;;",
		"  *)",
		"    echo \"usage: sm-clone owner/repo\" >&2",
		"    exit 1",
		"    ;;",
		"esac",
		"exec git clone \"git@github.com:$1.git\"",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(binDir, "sm-clone"), []byte(cloneScript), 0o700); err != nil {
		return err
	}

	editorWrapper := strings.Join([]string{
		"#!/usr/bin/env sh",
		"exec vi \"$@\"",
		"",
	}, "\n")
	for _, name := range []string{"vim", "nano", "pico"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(editorWrapper), 0o700); err != nil {
			return err
		}
	}

	return nil
}

func (m Model) spawnSSHShell(ss *SSHState) tea.Cmd {
	if embeddedCloudShellAvailableFn() {
		return m.spawnEmbeddedSSHShell(ss)
	}
	return m.spawnDockerSSHShell(ss)
}

func (m Model) spawnEmbeddedSSHShell(ss *SSHState) tea.Cmd {
	cmd := exec.Command(cloudShellEntrypoint)
	cmd.Dir = ss.TempDir
	cmd.Env = append(os.Environ(), sshShellEnv(ss, ss.TempDir)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return SSHShellExitMsg{Err: err}
	})
}

func (m Model) spawnDockerSSHShell(ss *SSHState) tea.Cmd {
	image := cloudShellImageRefFn()
	args := dockerSSHShellArgs(ss, image)

	cmd := exec.Command("docker", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return SSHShellExitMsg{Err: err}
	})
}

func dockerSSHShellArgs(ss *SSHState, image string) []string {
	env := sshShellEnv(ss, "/shell")
	args := []string{"run", "--rm", "-it"}
	args = append(args, dockerRunIdentityMountArgs(ss.TempDir, "/shell")...)
	args = append(args, dockerRunUserArgs()...)
	args = append(args, dockerBindMountArgs(ss.TempDir, "/shell")...)
	args = append(args, "-w", "/shell")
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	args = append(args, image)
	return args
}
