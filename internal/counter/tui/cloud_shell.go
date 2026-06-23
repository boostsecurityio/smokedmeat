// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
)

const cloudShellImage = "smokedmeat-cloud-shell:latest"
const releaseCloudShellImage = "ghcr.io/boostsecurityio/smokedmeat-cloud-shell"
const cloudShellImageOverrideEnv = "SMOKEDMEAT_CLOUD_SHELL_IMAGE"
const cloudShellEntrypoint = "/usr/local/bin/sm-cloud-entrypoint"

var dockerHasImageFn = dockerHasImage
var embeddedCloudShellAvailableFn = embeddedCloudShellAvailable
var currentUserFn = user.Current
var cloudShellImageRefFn = cloudShellImageRef

func (m Model) executeCloudShell() (tea.Model, tea.Cmd) {
	cs := m.cloudState
	if cs == nil {
		m.AddOutput("error", "No active cloud session. Run 'pivot aws/gcp/azure' first.")
		return m, nil
	}
	if len(cs.RawCredentials) == 0 {
		m.AddOutput("error", "Cloud session has no usable credentials. Re-run pivot to get fresh creds.")
		return m, nil
	}

	if cs.TempDir != "" {
		if _, err := os.Stat(cs.TempDir); err == nil {
			age := time.Since(cs.PivotTime).Truncate(time.Second)
			m.AddOutput("info", fmt.Sprintf("Resuming %s cloud shell (session age: %s)", cs.Provider, age))
			if !cs.Expiry.IsZero() {
				remaining := time.Until(cs.Expiry).Truncate(time.Second)
				if remaining <= 0 {
					m.AddOutput("warning", "Credentials have expired! Commands may fail.")
				} else if remaining < 10*time.Minute {
					m.AddOutput("warning", fmt.Sprintf("Credentials expire in %s", remaining))
				}
			}
			return m, m.spawnCloudShell(cs)
		}
		cs.TempDir = ""
	}

	sessionsDir := filepath.Join(smokedmeatDir(), "cloud-shell", "sessions")
	if err := os.MkdirAll(sessionsDir, 0o700); err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to create cloud shell dir: %v", err))
		return m, nil
	}
	tmpDir, err := os.MkdirTemp(sessionsDir, "sm-cloud-*")
	if err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to create temp dir: %v", err))
		return m, nil
	}
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to set permissions on temp dir: %v", err))
		os.RemoveAll(tmpDir)
		return m, nil
	}
	cs.TempDir = tmpDir

	image := cloudShellImageRefFn()
	if !embeddedCloudShellAvailableFn() && cloudShellNeedsLocalImage() && !dockerHasImageFn(image) {
		m.AddOutput("error", fmt.Sprintf("Cloud shell requires the Docker image '%s'. Build it with 'make cloud-shell-image'.", image))
		os.RemoveAll(tmpDir)
		cs.TempDir = ""
		return m, nil
	}

	m.AddOutput("info", fmt.Sprintf("Entering %s cloud shell (Ctrl+D or 'exit' to return)", cs.Provider))
	return m, m.spawnCloudShell(cs)
}

// ---------------------------------------------------------------------------
// Local cloud shell setup (fallback when Docker image is unavailable)
// ---------------------------------------------------------------------------

func setupLocalCloudShell(cs *CloudState) error {
	switch cs.Provider {
	case "k8s", "kubernetes":
		return setupLocalK8sShell(cs)
	default:
		return writeLocalBashRC(cs, localEnvVars(cs))
	}
}

func localEnvVars(cs *CloudState) map[string]string {
	env := make(map[string]string)
	switch cs.Provider {
	case "aws":
		for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"} {
			if v := cs.RawCredentials[key]; v != "" {
				env[key] = v
			}
		}
	case "gcp", "google":
		if v := cs.RawCredentials["ACCESS_TOKEN"]; v != "" {
			env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = v
			env["GOOGLE_OAUTH_ACCESS_TOKEN"] = v
		} else if path := materializeGCPExternalAccountConfig(cs, cs.TempDir); path != "" {
			env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] = path
			env["GOOGLE_APPLICATION_CREDENTIALS"] = path
		}
		if v := gcpProjectFromCreds(cs.RawCredentials); v != "" {
			env["CLOUDSDK_CORE_PROJECT"] = v
			env["GCLOUD_PROJECT"] = v
			env["GOOGLE_CLOUD_PROJECT"] = v
		}
		if v := cs.RawCredentials["SERVICE_ACCOUNT"]; v != "" {
			env["SM_GCP_ACCOUNT"] = v
		}
	case "azure", "az":
		if v := cs.RawCredentials["ACCESS_TOKEN"]; v != "" {
			env["ARM_ACCESS_TOKEN"] = v
		}
		if v := cs.RawCredentials["TENANT_ID"]; v != "" {
			env["ARM_TENANT_ID"] = v
		}
		if v := cs.RawCredentials["SUBSCRIPTION_ID"]; v != "" {
			env["ARM_SUBSCRIPTION_ID"] = v
		}
	default:
		for k, v := range cs.RawCredentials {
			switch k {
			case "Expiration", "EXPIRES_ON", "CREDENTIAL_CONFIG_JSON":
				continue
			}
			env[k] = v
		}
	}
	return env
}

func setupLocalK8sShell(cs *CloudState) error {
	kubeDir := filepath.Join(cs.TempDir, "kube")
	if err := os.MkdirAll(kubeDir, 0o700); err != nil {
		return err
	}

	server := cs.RawCredentials["SERVER"]
	token := cs.RawCredentials["BEARER_TOKEN"]
	if server == "" || token == "" {
		return fmt.Errorf("missing required Kubernetes credentials: SERVER and BEARER_TOKEN must be set")
	}

	kubeconfig := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []map[string]interface{}{
			{
				"name": "sm-cluster",
				"cluster": map[string]interface{}{
					"server":                   server,
					"insecure-skip-tls-verify": true,
				},
			},
		},
		"users": []map[string]interface{}{
			{
				"name": "sm-user",
				"user": map[string]interface{}{
					"token": token,
				},
			},
		},
		"contexts": []map[string]interface{}{
			{
				"name": "sm-context",
				"context": map[string]interface{}{
					"cluster": "sm-cluster",
					"user":    "sm-user",
				},
			},
		},
		"current-context": "sm-context",
	}

	kubeconfigData, err := json.MarshalIndent(kubeconfig, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(kubeDir, "config"), kubeconfigData, 0o600); err != nil {
		return err
	}

	env := map[string]string{"KUBECONFIG": "$HOME/kube/config"}
	return writeLocalBashRC(cs, env)
}

func writeLocalBashRC(cs *CloudState, env map[string]string) error {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	fmt.Fprintf(&b, "export HOME=\"${HOME:-%s}\"\n", shellEscape(cs.TempDir))
	fmt.Fprintf(&b, "export PS1='[sm:%s/%s] \\w\\$ '\n", shellEscape(cs.Provider), shellEscape(cs.Method))
	b.WriteString("cd \"$HOME\"\n")

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "export %s='%s'\n", k, shellEscape(env[k]))
	}

	fmt.Fprintf(&b, "echo 'SmokedMeat Cloud Shell (%s via %s)'\n", cs.Provider, cs.Method)
	return os.WriteFile(filepath.Join(cs.TempDir, ".bashrc"), []byte(b.String()), 0o600)
}

// ---------------------------------------------------------------------------
// Shell spawning
// ---------------------------------------------------------------------------

func dockerHasImage(image string) bool {
	cmd := exec.Command("docker", "image", "inspect", image)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func embeddedCloudShellAvailable() bool {
	info, err := os.Stat(cloudShellEntrypoint)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}

func cloudShellImageRef() string {
	if image := strings.TrimSpace(os.Getenv(cloudShellImageOverrideEnv)); image != "" {
		return image
	}
	if buildinfo.IsDevVersion() {
		return cloudShellImage
	}
	return releaseCloudShellImage + ":" + buildinfo.Version
}

func cloudShellNeedsLocalImage() bool {
	return strings.TrimSpace(os.Getenv(cloudShellImageOverrideEnv)) == "" && buildinfo.IsDevVersion()
}

func dockerRunUserArgs() []string {
	current, ok := currentNumericUser()
	if !ok {
		return nil
	}
	return []string{"--user", current.Uid + ":" + current.Gid}
}

func currentNumericUser() (*user.User, bool) {
	if runtime.GOOS == "windows" {
		return nil, false
	}

	current, err := currentUserFn()
	if err != nil {
		return nil, false
	}
	if _, err := strconv.ParseUint(current.Uid, 10, 32); err != nil {
		return nil, false
	}
	if _, err := strconv.ParseUint(current.Gid, 10, 32); err != nil {
		return nil, false
	}
	return current, true
}

func dockerRunIdentityMountArgs(hostDir, containerHome string) []string {
	current, ok := currentNumericUser()
	if !ok || current.Uid == "0" {
		return nil
	}
	if err := writeDockerRunIdentityFiles(hostDir, containerHome, current.Uid, current.Gid); err != nil {
		return nil
	}
	return []string{
		"--mount", "type=bind,source=" + filepath.Join(hostDir, ".sm-passwd") + ",target=/etc/passwd,readonly",
		"--mount", "type=bind,source=" + filepath.Join(hostDir, ".sm-group") + ",target=/etc/group,readonly",
	}
}

func writeDockerRunIdentityFiles(hostDir, containerHome, uid, gid string) error {
	passwd := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/sh",
		fmt.Sprintf("smokedmeat:x:%s:%s:SmokedMeat Shell:%s:/bin/bash", uid, gid, containerHome),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(hostDir, ".sm-passwd"), []byte(passwd), 0o644); err != nil {
		return err
	}

	group := strings.Join([]string{
		"root:x:0:",
		fmt.Sprintf("smokedmeat:x:%s:", gid),
		"",
	}, "\n")
	return os.WriteFile(filepath.Join(hostDir, ".sm-group"), []byte(group), 0o644)
}

func dockerBindMountArgs(source, target string) []string {
	return []string{"--mount", "type=bind,source=" + source + ",target=" + target}
}

func (m Model) spawnCloudShell(cs *CloudState) tea.Cmd {
	if embeddedCloudShellAvailableFn() {
		return m.spawnEmbeddedCloudShell(cs)
	}
	return m.spawnDockerCloudShell(cs)
}

func (m Model) spawnEmbeddedCloudShell(cs *CloudState) tea.Cmd {
	shareDir := cloudShellShareDir(cs)
	_ = os.MkdirAll(shareDir, 0o700)

	cmd := exec.Command(cloudShellEntrypoint)
	cmd.Dir = cs.TempDir
	cmd.Env = append(os.Environ(), cloudShellEnv(cs, cs.TempDir, shareDir)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		cleanupCloudShellShareDir(shareDir)
		return CloudShellExitMsg{Err: err}
	})
}

func (m Model) spawnDockerCloudShell(cs *CloudState) tea.Cmd {
	shareDir := cloudShellShareDir(cs)
	_ = os.MkdirAll(shareDir, 0o700)

	image := cloudShellImageRefFn()
	args := dockerCloudShellArgs(cs, shareDir, image)

	cmd := exec.Command("docker", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		cleanupCloudShellShareDir(shareDir)
		return CloudShellExitMsg{Err: err}
	})
}

func dockerCloudShellArgs(cs *CloudState, shareDir, image string) []string {
	env := cloudShellEnv(cs, "/shell", "/shared")
	args := []string{"run", "--rm", "-it"}
	args = append(args, dockerRunIdentityMountArgs(cs.TempDir, "/shell")...)
	args = append(args, dockerRunUserArgs()...)
	args = append(args, dockerBindMountArgs(cs.TempDir, "/shell")...)
	args = append(args, dockerBindMountArgs(shareDir, "/shared")...)
	args = append(args, "-w", "/shell")
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	args = append(args, image)
	return args
}

func cloudShellShareDir(cs *CloudState) string {
	sessionID := filepath.Base(cs.TempDir)
	return filepath.Join(smokedmeatDir(), "cloud-shell", "shared", sessionID)
}

func cleanupCloudShellShareDir(shareDir string) {
	entries, _ := os.ReadDir(shareDir)
	if len(entries) == 0 {
		os.RemoveAll(shareDir)
	}
}

func cloudShellEnv(cs *CloudState, shellHome, sharedDir string) []string {
	env := []string{
		"HOME=" + shellHome,
		"SM_SHELL_HOME=" + shellHome,
		"SM_SHARED=" + sharedDir,
		"SM_PROVIDER=" + cs.Provider,
		"SM_METHOD=" + cs.Method,
	}
	if !cs.Expiry.IsZero() {
		remaining := time.Until(cs.Expiry).Truncate(time.Second)
		if remaining > 0 {
			env = append(env, "SM_EXPIRY="+remaining.String())
		} else {
			env = append(env, "SM_EXPIRY=EXPIRED")
		}
	}

	switch cs.Provider {
	case "aws":
		for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"} {
			if v := cs.RawCredentials[key]; v != "" {
				env = append(env, key+"="+v)
			}
		}
	case "gcp", "google":
		if v := cs.RawCredentials["ACCESS_TOKEN"]; v != "" {
			env = append(env, "CLOUDSDK_AUTH_ACCESS_TOKEN="+v, "GOOGLE_OAUTH_ACCESS_TOKEN="+v)
		} else if path := materializeGCPExternalAccountConfig(cs, shellHome); path != "" {
			env = append(env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="+path, "GOOGLE_APPLICATION_CREDENTIALS="+path)
		}
		if v := gcpProjectFromCreds(cs.RawCredentials); v != "" {
			env = append(env,
				"CLOUDSDK_CORE_PROJECT="+v,
				"GCLOUD_PROJECT="+v,
				"GOOGLE_CLOUD_PROJECT="+v,
			)
		}
		if v := cs.RawCredentials["SERVICE_ACCOUNT"]; v != "" {
			env = append(env, "SM_GCP_ACCOUNT="+v)
		}
		env = append(env, "CLOUDSDK_CONFIG="+filepath.Join(shellHome, "gcloud"), "BOTO_CONFIG="+filepath.Join(shellHome, ".boto"))
	case "azure", "az":
		if v := cs.RawCredentials["ACCESS_TOKEN"]; v != "" {
			env = append(env, "ARM_ACCESS_TOKEN="+v)
		}
		if v := cs.RawCredentials["TENANT_ID"]; v != "" {
			env = append(env, "ARM_TENANT_ID="+v)
		}
		if v := cs.RawCredentials["SUBSCRIPTION_ID"]; v != "" {
			env = append(env, "ARM_SUBSCRIPTION_ID="+v)
		}
	}
	return env
}

func materializeGCPExternalAccountConfig(cs *CloudState, shellHome string) string {
	if cs == nil || cs.TempDir == "" {
		return ""
	}
	data := strings.TrimSpace(cs.RawCredentials["CREDENTIAL_CONFIG_JSON"])
	if data == "" {
		return ""
	}
	hostPath := filepath.Join(cs.TempDir, "google-application-credentials.json")
	if err := os.WriteFile(hostPath, []byte(data), 0o600); err != nil {
		return ""
	}
	return filepath.Join(shellHome, "google-application-credentials.json")
}

func gcpProjectFromCreds(raw map[string]string) string {
	if raw == nil {
		return ""
	}
	for _, key := range []string{"PROJECT", "GCP_PROJECT_ID", "GCLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"} {
		if v := strings.TrimSpace(raw[key]); v != "" {
			return v
		}
	}
	return extractGCPProjectFromServiceAccount(raw["SERVICE_ACCOUNT"])
}
