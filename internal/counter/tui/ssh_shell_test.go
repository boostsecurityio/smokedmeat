// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
)

func TestExecuteSSHShell_NoAgentNotRequired(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	oldVersion := buildinfo.Version
	dockerHasImageFn = func(string) bool { return true }
	embeddedCloudShellAvailableFn = func() bool { return false }
	buildinfo.Version = "dev"
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
		buildinfo.Version = oldVersion
	})

	m := Model{
		output: []OutputLine{},
		sshState: &SSHState{
			KeyName:        "DEPLOY_KEY",
			KeyValue:       testSSHPrivateKey(t),
			KeyType:        "ssh-rsa",
			KeyFingerprint: "SHA256:test",
			PivotTime:      time.Now(),
			Scope:          "acme/private-infra",
			Results: []SSHTrialResult{
				{Repo: "acme/private-infra", Success: true, Permission: "write"},
				{Repo: "acme/private-docs", Success: true, Permission: "read"},
			},
		},
	}

	result, cmd := m.executeSSHShell()
	rm := result.(Model)

	require.NotNil(t, cmd)
	require.NotNil(t, rm.sshState)
	assert.NotEmpty(t, rm.sshState.TempDir)
	_, err := os.Stat(filepath.Join(rm.sshState.TempDir, ".ssh", "config"))
	assert.NoError(t, err)
	var outputLines []string
	for _, line := range rm.output {
		outputLines = append(outputLines, line.Content)
	}
	joinedOutput := strings.Join(outputLines, "\n")
	assert.Contains(t, joinedOutput, "Git identity ready")
	assert.Contains(t, joinedOutput, "Confirmed write repos: 1")
	assert.Contains(t, joinedOutput, "Confirmed read-only repos: 1")
	assert.Contains(t, joinedOutput, "sm-context | sm-clone owner/repo | vim | nano")
	if rm.sshState.TempDir != "" {
		_ = os.RemoveAll(rm.sshState.TempDir)
	}
}

func TestExecuteSSHShell_ReleasePullsMatchingImage(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	oldVersion := buildinfo.Version
	dockerHasImageFn = func(string) bool { return false }
	embeddedCloudShellAvailableFn = func() bool { return false }
	buildinfo.Version = "1.2.3"
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
		buildinfo.Version = oldVersion
	})

	m := Model{
		output: []OutputLine{},
		sshState: &SSHState{
			KeyName:        "DEPLOY_KEY",
			KeyValue:       testSSHPrivateKey(t),
			KeyType:        "ssh-rsa",
			KeyFingerprint: "SHA256:test",
			PivotTime:      time.Now(),
			Scope:          "acme/private-infra",
			Results: []SSHTrialResult{
				{Repo: "acme/private-infra", Success: true, Permission: "write"},
			},
		},
	}

	result, cmd := m.executeSSHShell()
	rm := result.(Model)

	require.NotNil(t, cmd)
	require.NotNil(t, rm.sshState)
	assert.NotEmpty(t, rm.sshState.TempDir)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "sm-context | sm-clone owner/repo | vim | nano")
}

func TestSetupSSHShellHome_WritesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &SSHState{
		KeyName:        "DEPLOY_KEY",
		KeyValue:       testSSHPrivateKey(t),
		KeyType:        "ssh-rsa",
		KeyFingerprint: "SHA256:test",
		TempDir:        tmpDir,
		Results: []SSHTrialResult{
			{Repo: "acme/private-infra", Success: true, Permission: "write"},
			{Repo: "acme/private-docs", Success: true, Permission: "read"},
		},
	}

	require.NoError(t, setupSSHShellHome(ss))

	keyData, err := os.ReadFile(filepath.Join(tmpDir, ".ssh", "id_smokedmeat"))
	require.NoError(t, err)
	assert.Contains(t, string(keyData), "BEGIN RSA PRIVATE KEY")

	configData, err := os.ReadFile(filepath.Join(tmpDir, ".ssh", "config"))
	require.NoError(t, err)
	assert.Contains(t, string(configData), "StrictHostKeyChecking yes")
	assert.NotContains(t, string(configData), "IdentityFile")
	assert.NotContains(t, string(configData), "UserKnownHostsFile")

	knownHostsData, err := os.ReadFile(filepath.Join(tmpDir, ".ssh", "known_hosts"))
	require.NoError(t, err)
	assert.Contains(t, string(knownHostsData), "github.com ssh-ed25519")

	gitConfigData, err := os.ReadFile(filepath.Join(tmpDir, ".gitconfig"))
	require.NoError(t, err)
	assert.Contains(t, string(gitConfigData), "smokedmeat@example.com")
	assert.NotContains(t, string(gitConfigData), "sshCommand")

	writeReposData, err := os.ReadFile(filepath.Join(tmpDir, ".sm-write-repos"))
	require.NoError(t, err)
	assert.Contains(t, string(writeReposData), "acme/private-infra")

	readReposData, err := os.ReadFile(filepath.Join(tmpDir, ".sm-read-repos"))
	require.NoError(t, err)
	assert.Contains(t, string(readReposData), "acme/private-docs")

	contextScriptData, err := os.ReadFile(filepath.Join(tmpDir, "bin", "sm-context"))
	require.NoError(t, err)
	assert.Contains(t, string(contextScriptData), "Write repos:")

	cloneScriptData, err := os.ReadFile(filepath.Join(tmpDir, "bin", "sm-clone"))
	require.NoError(t, err)
	assert.Contains(t, string(cloneScriptData), "git@github.com:$1.git")

	vimScriptData, err := os.ReadFile(filepath.Join(tmpDir, "bin", "vim"))
	require.NoError(t, err)
	assert.Contains(t, string(vimScriptData), "exec vi")

	nanoScriptData, err := os.ReadFile(filepath.Join(tmpDir, "bin", "nano"))
	require.NoError(t, err)
	assert.Contains(t, string(nanoScriptData), "exec vi")
}

func TestSSHShellEnv_UsesRuntimeScopedKeyPaths(t *testing.T) {
	ss := &SSHState{
		KeyFingerprint: "SHA256:test",
		Scope:          "acme/private-infra",
	}

	env := sshShellEnv(ss, "/shell")
	joined := "\n" + strings.Join(env, "\n") + "\n"

	assert.Contains(t, joined, "\nHOME=/shell\n")
	assert.Contains(t, joined, "\nPATH=/shell/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	assert.Contains(t, joined, "\nSM_SSH_IDENTITY=/shell/.ssh/id_smokedmeat\n")
	assert.Contains(t, joined, "\nSM_SSH_KNOWN_HOSTS=/shell/.ssh/known_hosts\n")
	assert.Contains(t, joined, "\nGIT_SSH_COMMAND=ssh -o IdentitiesOnly=yes -o IdentityFile=/shell/.ssh/id_smokedmeat -o UserKnownHostsFile=/shell/.ssh/known_hosts -o StrictHostKeyChecking=yes -o LogLevel=ERROR\n")
}

func TestDockerSSHShellArgs_MountsUserDatabase(t *testing.T) {
	oldCurrentUser := currentUserFn
	currentUserFn = func() (*user.User, error) {
		return &user.User{Uid: "501", Gid: "20"}, nil
	}
	t.Cleanup(func() {
		currentUserFn = oldCurrentUser
	})

	tmpDir := t.TempDir()
	ss := &SSHState{
		KeyFingerprint: "SHA256:test",
		Scope:          "repo:whooli/infrastructure-definitions",
		TempDir:        tmpDir,
	}

	args := dockerSSHShellArgs(ss, "smokedmeat-cloud-shell:test")
	joined := "\n" + strings.Join(args, "\n") + "\n"

	if runtime.GOOS == "windows" {
		assert.NotContains(t, joined, "target=/etc/passwd")
		assert.NotContains(t, joined, "\n--user\n")
		return
	}

	assert.Contains(t, joined, "\ntype=bind,source="+filepath.Join(tmpDir, ".sm-passwd")+",target=/etc/passwd,readonly\n")
	assert.Contains(t, joined, "\ntype=bind,source="+filepath.Join(tmpDir, ".sm-group")+",target=/etc/group,readonly\n")
	assert.Contains(t, joined, "\n--user\n501:20\n")
	assert.Contains(t, joined, "\ntype=bind,source="+tmpDir+",target=/shell\n")
	assert.Contains(t, joined, "\nGIT_SSH_COMMAND=ssh -o IdentitiesOnly=yes -o IdentityFile=/shell/.ssh/id_smokedmeat -o UserKnownHostsFile=/shell/.ssh/known_hosts -o StrictHostKeyChecking=yes -o LogLevel=ERROR\n")
	assert.Equal(t, "smokedmeat-cloud-shell:test", args[len(args)-1])

	passwd, err := os.ReadFile(filepath.Join(tmpDir, ".sm-passwd"))
	require.NoError(t, err)
	assert.Contains(t, string(passwd), "smokedmeat:x:501:20:SmokedMeat Shell:/shell:/bin/bash")
}

func TestSSHShellExitRestoresInputFocus(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.focus = FocusSessions
	m.paneFocus = PaneFocusActivity

	result, _ := m.Update(SSHShellExitMsg{})
	rm := result.(Model)

	assert.Equal(t, FocusInput, rm.focus)
	assert.True(t, rm.input.Focused())
	assert.Equal(t, -1, rm.historyIndex)
	assert.Empty(t, rm.completionHint)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "SSH shell closed")
}
