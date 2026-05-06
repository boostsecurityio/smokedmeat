# "Gone in 180 Seconds" YouTube Video

This is the director's commentary script for the published "Gone in 180 Seconds" screencast. The recording is closer to 3:47 end to end, but the thumbnail and title focus on the 180 second exploit arc: public repo foothold, private repo pivot, OIDC cloud access, and flag capture.

The thumbnail promise:

```text
Public repo -> private repos -> OIDC / cloud
Gone in 180 seconds
```

The actual video story:

```text
Showcase the Whooli GitHub organization as the CTF target
-> SmokedMeat repo README "Quick Start" section
-> copy Quick Start commands
-> git clone / make quickstart
-> Counter setup asks for a Personal Access Token
-> set target organization to whooli
-> embedded Poutine analysis finds public repo vulnerabilities
-> pick the highlighted comment injection
-> injected comment triggers GitHub Actions
-> wait for the first callback
-> Post-Exploit loot contains a GitHub App private key
-> pivot using the app key
-> auto-reanalyze whooli to discover private repos
-> confirm the new vantage point in the browser graph
-> switch to benchmark-bot.yml in the private infrastructure repo
-> configure cache poisoning against deploy.yml
-> flush cache and arm 2 minute dwell mode
-> wait until the cache is poisoned
-> trigger deploy.yml as the victim workflow
-> wait for post-checkout execution and callback
-> pivot gcp exchanges the victim workflow's OIDC token
-> cloud shell opens a preconfigured Google Cloud shell
-> list visible buckets
-> read the CTF flag from Cloud Storage
```

## Preflight

Use a large terminal and browser with only the needed tabs visible. Keep the graph browser tab available after the first pivot.

Prepare:

- Browser tab at `https://github.com/whooli`
- Browser tab at `https://github.com/boostsecurityio/smokedmeat`
- Terminal in a neutral working directory
- Classic GitHub PAT with public_repo scope ready in clipboard or password manager
- Browser authenticated to GitHub so Actions pages open without friction
- Zoom tool or editor keyframes ready for README, Counter loot, Actions logs, and flag output

## Published Timeline

```text
00:01 - Open github.com/whooli and identify the target organization for the CTF
00:09 - Switch to the github.com/boostsecurityio/smokedmeat repo and scroll to Quick Start section in the README
00:15 - Copy Quick Start commands into the terminal
00:23 - Run the commands which git clone and run `make quickstart`, letting Docker containers start
00:30 - The C2 tunnel container starts as part of quickstart
00:36 - Once SmokedMeat's "Counter" TUI is started it asks for an operator Personal Access Token
00:40 - Set target type to Organization and target to whooli
00:45 - Embeeded `poutine` engine analyzes public repos and highlights exploitable vulnerabilities
00:51 - Select the public comment injection vulnerability by pressing `1` on the keyboard (as seen in the menu)
00:58 - Clarify that one shall only proceed if they are authorized before exploiting (in this case, this is a CTF)
01:06 - Show the injected comment and triggered GitHub Actions workflow run logs
01:15 - Wait for the workflow to finish and the TUI switches automatically to Post-Exploit phase
01:23 - The Loot Stash shows secrets, including a GitHub App private key
01:29 - Pivot to the app key
01:32 - Re-analysis discovers private repos and additional vulnerabilities
01:38 - Open the graph to show public-to-private expansion
01:47 - Select the benchmark bot vulnerability in the private infrastructure repo
01:55 - Configure cache poisoning against the deploy workflow
02:08 - Flush cache and set dwell mode to 2 minutes
02:17 - Wait while the cache poisoning payload runs
02:25 - Show cache state changing from empty to poisoned
02:37 - Arm the next dwell callback using deploy.yml
02:47 - Trigger deploy.yml and wait
02:55 - Explain the longer wait for cache restore and post-checkout execution
03:11 - Return to Post-Exploit with about 2 minutes of dwell available
03:18 - Run pivot gcp to exchange the OIDC token
03:27 - Run cloud shell
03:36 - List accessible buckets
03:47 - Read the CTF flag
```

## Operator Commands

Quick Start copy block:

```bash
git clone https://github.com/boostsecurityio/smokedmeat.git
cd smokedmeat
make quickstart
```

SmokedMeat's "Counter" setup:

```text
PAT: paste masked token (`************`)
Target type: Organization
Target: whooli
Analyze: start
```

Public App-key foothold:

If the first menu item is already the comment foothold that lands on `whooli-analyzer.yml`, selecting `1` is fine. The recording selects the highlighted injection path and then shows the GitHub Actions workflow triggered by the injected comment.

GitHub App pivot:

Highlight the GitHub App private key in the Loot Stash and press `p` to pivot. The pivot re-analyzes Whooli and discovers private repos.

Private repo target:

Identify the vulnerability in the private infrastructure repo, jump to it using the omnibox search dialog (by pressing `/`) then press `x` to exploit it:

```text
.github/workflows/benchmark-bot.yml
```

Cache poison path:

In the exploit wizard, for the vulnerable `benchmark-bot.yml` workflow set it as cache poisoning writer. Set `deploy.yml` as the victim, instrut it to flush the cache using the GitHub App identity's `actions: write` permission, and pre-arm "Dwell" mode to 2 minutes.

```text
Cache Poisoning: On
Replace Cache: On
Writer: .github/workflows/benchmark-bot.yml
Victim: .github/workflows/deploy.yml
Dwell time: 2 minutes
```

Dispatch to trap the victim:

Using the tree (or omnibox), highlight the `deploy.yml` workflow and press `x` to exploit again. This dispatches the victim workflow. The recording waits longer here because the victim has to restore the poisoned cache and reach the post-checkout phase at the end where the exploit will run and linger for 2 minutes.

Cloud pivot:

After the victim callback arrives, use the 2 minute dwell window to exchange the workflow's OIDC token for Google Cloud access. Press `Tab` to set focus on the command input box.

```text
pivot gcp
cloud shell
gsutil ls
gsutil ls gs://whooli-newcleus-benchmarks
gsutil cat gs://whooli-newcleus-benchmarks/flag.txt
```

## Shot Detail

### 1. Whooli and SmokedMeat's README to Terminal

Start in the browser at the Whooli GitHub organization:

```text
https://github.com/whooli
```

Briefly identify Whooli as the authorized CTF target.

Switch to the SmokedMeat repo:

```text
https://github.com/boostsecurityio/smokedmeat
```

Scroll down to the **Quick Start** section in the README. The viewer should clearly see that no local setup knowledge is required beyond copying the commands.

Cut to terminal and paste:

```bash
git clone https://github.com/boostsecurityio/smokedmeat.git
cd smokedmeat
make quickstart
```

Use speed ramping through clone, image pulls, and quickstart startup. The viewer only needs to understand that `make quickstart` starts the C2 tunnel, Kitchen, and SmokedMeat's "Counter" TUI.

### 2. Counter Setup

Once Counter starts:

1. Paste a masked Classic PAT with `public_repo` scope.
2. Pick `Organization`.
3. Type `whooli`.
4. Start analysis.

Frame the wizard so the target type and `whooli` are readable.

### 3. Public Repo Analysis and First Exploit

After setup, Counter runs the embedded `poutine` engine against Whooli's public repos.

Show:

```text
Loaded attack graph
Highlighted injection vulnerability
```

Select the highlighted comment injection by pressing `1`, matching the visible menu. Narration should include the authorization boundary before proceeding.

Cut to GitHub Actions and show the injected comment triggering the `whooli-analyzer.yml` workflow run. The recording notes that this first workflow typically takes about 20 seconds.

### 4. First Post-Exploit and App-Key Pivot

When Counter enters Post-Exploit, zoom the Loot Stash.

Show:

```text
GitHub App Private Key
```

Highlight the GitHub App private key and press `p` to pivot. Counter re-analyzes Whooli from the GitHub App identity and discovers private repos plus additional vulnerabilities.

### 5. Graph Confirmation

Open the browser graph view after the pivot.

The graph should communicate:

```text
Started from public repos
Discovered private repos after the app-key pivot
New vulnerability path is now reachable
```

This shot aligns with the thumbnail's public repo to private repos beat.

### 6. Private Workflow Cache Poisoning

Return to Counter and use the tree or omnibox search dialog to select the private infrastructure repo path.

Target:

```text
.github/workflows/benchmark-bot.yml
```

Press `x` to exploit and configure cache poisoning in the exploit wizard:

```text
Cache Poisoning: On
Replace Cache: On
Writer: .github/workflows/benchmark-bot.yml
Victim: .github/workflows/deploy.yml
Dwell time: 2 minutes
```

The `benchmark-bot.yml` workflow is the writer. The victim is `deploy.yml`. Keep the empty-to-poisoned cache state visible because it explains why the next workflow run is a trapped victim, not a second direct injection.

### 7. Trigger Victim Workflow

Switch to "Arm the next Dwell callback" and choose:

```text
.github/workflows/deploy.yml
```

Trigger it from Counter by highlighting the workflow and pressing `x` again. The recording explains that this wait is longer because the victim workflow must restore the poisoned cache and run through the post-checkout phase before the exploit runs.

When the callback lands, Counter returns to Post-Exploit with about 2 minutes of dwell available.

### 8. OIDC Pivot and Flag Capture

Press `Tab` to focus the command input box.

Run:

```text
pivot gcp
cloud shell
gsutil ls
gsutil ls gs://whooli-newcleus-benchmarks
gsutil cat gs://whooli-newcleus-benchmarks/flag.txt
```

The video shows three accessible buckets, then reads the CTF flag from the benchmark bucket.

Final frame:

```text
FLAG_SM{...}
```

## One Sentence Narration

From a public GitHub Actions comment injection in Whooli's CTF organization, SmokedMeat captures a GitHub App key, pivots into private repos, poisons the trusted deploy workflow cache, exchanges the victim workflow's OIDC identity for Google Cloud access, and reads the CTF flag from Cloud Storage.
