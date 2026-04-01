# dependency-diagnostic

A simple security check for Node and Python projects. Looks at how your dependencies are configured and flags common supply chain attack exposures.

No tools to install. Just run the script or paste the commands into your terminal.

## Why this exists

In March 2026, axios (100M weekly npm downloads) and litellm (3.4M daily PyPI downloads) were both compromised in supply chain attacks. Anyone who installed them during a brief window had credentials, API keys, and SSH keys silently exfiltrated.

If you use coding assistants to build projects, they install libraries on your behalf - often hundreds of them. This diagnostic checks whether your project is configured to limit exposure when (not if) the next attack happens.

## What it checks

| # | Check | What it looks for |
|---|-------|-------------------|
| 1 | **Lockfile** | Is your dependency tree frozen to known versions, or does every install resolve from the live registry? |
| 2 | **Version pinning** | Are you using range specifiers (`^`, `~`, `>=`) that automatically pull in new versions? |
| 3 | **Install scripts** | Can packages run arbitrary code on your machine during installation? |
| 4 | **Attack surface** | How many total packages (including transitive) are in your dependency tree? |
| 5 | **Registry config** | Is your setup vulnerable to dependency confusion or leaking auth tokens? |
| 6 | **Known vulnerabilities** | Do any current dependencies have disclosed CVEs? |

## Usage
Run the diagnostic from your project's root directory.

### Node / npm
Copy the quick-run block from [CHECKS.md](CHECKS.md#node--npm-project) and paste it into your terminal.

### Python
Copy the quick-run block from [CHECKS.md](CHECKS.md#python-project) and paste it into your terminal.
