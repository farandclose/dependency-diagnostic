# Checks Reference

Detailed explanation of each check in the diagnostic - what it tests, why it matters, and how to fix failures.

For a quick PASS/FAIL readout, skip to the [quick-run diagnostic](#quick-run-diagnostic) at the bottom.

---

## Check 1: Lockfile exists and is committed

When you run `npm install` or `pip install`, the package manager resolves your dependency specs to specific versions and downloads them. A **lockfile** is a snapshot of that resolution - it records exactly which version of every package (including transitive dependencies) was installed, along with integrity hashes.

Without a lockfile, every install is a fresh resolution against the live registry. If an attacker published a poisoned version 10 minutes ago and it satisfies your version spec, you get it.

With a lockfile, you get exactly what was recorded. The registry's current state is irrelevant.

### Node / npm

```bash
# Does a lockfile exist?
ls package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null || echo "FAIL: no lockfile found"

# Is it committed to git (not gitignored)?
git check-ignore package-lock.json 2>/dev/null && echo "FAIL: lockfile is gitignored" || echo "OK: lockfile is tracked"

# Are CI scripts and Dockerfiles using npm ci (safe) or npm install (unsafe)?
grep -rn "npm install" .github/ Makefile Dockerfile scripts/ 2>/dev/null
# Any hit here is suspect - should be "npm ci" instead
```

**Why `npm ci` matters:** `npm install` can silently update the lockfile, pulling in newer versions. `npm ci` reads the lockfile and installs exactly what's recorded, or fails. In CI and Docker builds, you always want `npm ci`.

**To fix:** If no lockfile exists, run `npm install` once to generate it, commit it, then use `npm ci` everywhere going forward.

### Python

```bash
# Does a lockfile exist? (any of these count)
ls requirements.txt poetry.lock uv.lock Pipfile.lock 2>/dev/null || echo "FAIL: no lockfile found"

# If requirements.txt exists, does it have hashes?
[ -f requirements.txt ] && grep -q "\-\-hash=" requirements.txt && echo "OK: hashes present" || echo "FAIL: no hash verification"

# Is the lockfile committed?
git check-ignore requirements.txt poetry.lock uv.lock Pipfile.lock 2>/dev/null
```

**Why hashes matter:** Without hashes, pip downloads whatever the registry serves and trusts it blindly. With hashes, pip verifies the downloaded file matches a known checksum - a tampered package fails the check.

**Critical gotcha:** pip only enforces hash checking when EVERY requirement in the file has a hash. A single unhashed line silently disables verification for the entire file. Generate hashes for everything: `uv pip compile --generate-hashes requirements.in > requirements.txt`

**Verdict:**
- Lockfile exists + committed + CI uses `npm ci` (or pip install with hashes) = PASS
- Lockfile missing, gitignored, unhashed, or CI bypasses it = FAIL

---

## Check 2: Versions are pinned exactly

Range specifiers like `^1.14.0` (npm) or `>=1.64.0` (pip) mean "give me any compatible version." This is the mechanism by which supply chain attacks propagate - the attacker publishes a new version that falls within your range, and your next install picks it up automatically.

### Node / npm

```bash
# Find all dependencies using range specifiers
grep -E '"[\^~><=*]|"latest"' package.json

# Count them
grep -cE '"[\^~><=*]|"latest"' package.json 2>/dev/null || echo 0
```

**What each specifier means:**
- `"^1.14.0"` - any version >=1.14.0 and <2.0.0. An attacker publishes 1.14.1, you get it.
- `"~4.17.0"` - any version >=4.17.0 and <4.18.0. Narrower but still a range.
- `"*"` or `"latest"` - any version at all. Maximum exposure.
- `"1.14.0"` - exactly this version, always. This is what you want.

**To fix:** Remove `^` and `~` prefixes. Set `save-exact=true` in `.npmrc` so future `npm install --save` commands pin exact versions by default.

### Python

```bash
# Find range specifiers in requirements files
grep -E '>=|~=|<=|!=|[^=!<>~]>[^=]|[^=!<>~]<[^=]|\*' requirements.txt requirements.in 2>/dev/null

# Check pyproject.toml for unpinned deps
grep -E '>=|~=|<=|!=|>\s|<\s|\*' pyproject.toml 2>/dev/null | grep -v "python_requires"
```

**What each specifier means:**
- `litellm>=1.64.0` - any version from 1.64.0 onwards. This is what pulled in the poisoned litellm 1.82.8.
- `requests~=2.28` - any 2.28.x. Narrower but still a range.
- `*` - any version at all.
- `litellm==1.80.6` - exactly this version. This is what you want.

**Verdict:**
- Zero range specifiers in dependency declarations = PASS
- Any `^`, `~`, `>=`, `>`, `~=`, `*`, or `latest` = FAIL

---

## Check 3: Code execution during and after install is controlled

Packages can run arbitrary code on your machine at multiple points - during installation, and every time your application starts. Each is a separate attack vector.

### 3a. Install-time scripts (npm)

npm packages can include lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) that execute automatically during `npm install`. These are shell commands that run with your user's full permissions.

The axios attack delivered a cross-platform RAT via a `postinstall` script in a malicious dependency. Within 2 seconds of `npm install`, before npm had even finished resolving the rest of the tree, the script was already phoning home to the attacker's C2 server.

```bash
# Is ignore-scripts set at project level?
grep "ignore-scripts" .npmrc 2>/dev/null || echo "NOT SET in project .npmrc"

# Is it set at user level?
npm config get ignore-scripts 2>/dev/null
# If "false" (the default): you're exposed

# Which packages in your tree actually have install scripts?
# This tells you what WOULD run if scripts are enabled
npm pkg --workspaces --include-workspace-root get scripts 2>/dev/null | grep -E "preinstall|postinstall|install|prepare" || echo "No install scripts found in direct dependencies"

# For the full tree (including transitive deps):
ls node_modules/*/package.json 2>/dev/null | xargs grep -l '"preinstall"\|"postinstall"\|"install"' 2>/dev/null
```

**Why enumerating scripts matters:** Knowing `ignore-scripts` is off is one thing. Knowing that 14 packages in your tree have postinstall scripts - and which ones - lets you make an informed decision about what to whitelist.

**To fix:**
- Project-level: add `ignore-scripts=true` to `.npmrc`
- Global: `npm config set ignore-scripts true`
- When a specific package genuinely needs scripts (e.g., native bindings like `sharp`, `bcrypt`): install it explicitly with `npm install <package> --ignore-scripts=false`
- Set `save-exact=true` in `.npmrc` while you're at it

### 3b. Install-time code execution (Python)

Python packages distributed as source distributions (sdist / `.tar.gz`) run `setup.py` during install - arbitrary Python code with full system access. Packages distributed as wheels (`.whl`) are pre-built archives that install without executing code.

```bash
# Which of your dependencies installed from source (sdist) vs wheel?
pip install --dry-run -r requirements.txt 2>&1 | grep -i "\.tar\.gz\|sdist"
# Any hit means setup.py would execute during install

# Force wheel-only installs (fails if no wheel is available):
pip install --only-binary :all: -r requirements.txt
```

### 3c. Runtime auto-execution (Python .pth files)

The litellm attack used a different vector: a `.pth` file. Python automatically executes code in `.pth` files at interpreter startup - not just when you import the compromised package, but every time Python starts. The malicious `litellm_init.pth` ran a credential stealer on every Python process on the machine.

```bash
# List all .pth files in your Python environment
python3 -c "
import site, os, pathlib
for d in site.getsitepackages() + [site.getusersitepackages()]:
    p = pathlib.Path(d)
    if p.exists():
        for f in p.glob('*.pth'):
            print(f)
"

# Review any .pth file that contains import statements (these execute code):
python3 -c "
import site, pathlib
for d in site.getsitepackages() + [site.getusersitepackages()]:
    p = pathlib.Path(d)
    if p.exists():
        for f in p.glob('*.pth'):
            for line in f.read_text().splitlines():
                if line.strip().startswith('import'):
                    print(f'{f}: {line.strip()}')
"
```

**What you're looking for:** Most `.pth` files just contain directory paths (harmless). Any `.pth` file containing an `import` statement is executing code on every Python startup. Legitimate examples exist (e.g., `distutils-precedence.pth` in modern pip), but anything unexpected warrants investigation.

### 3d. Runtime module code (inherent risk - awareness, not a check)

In Python, any `import foo` statement executes all module-level code in `foo/__init__.py`. In Node, `require('foo')` or `import 'foo'` executes the package's entry point. This is inherent to how both languages work - there's no config to disable it. Even with install scripts disabled, a compromised package executes its malicious code the moment your application imports it.

This is the vector that lockfiles and pinning defend against. If you never install the bad version, its module code never runs.

**Verdict:**
- npm: `ignore-scripts=true` set + you know which packages need an exception = PASS
- npm: not set, or set but you haven't reviewed which packages have scripts = FAIL
- Python: installing from wheels + no unexpected `.pth` files with `import` statements = PASS
- Python: installing from sdist without review, or unknown `.pth` files present = FAIL

---

## Check 4: Attack surface size

Every dependency in your tree - including transitive ones you didn't ask for - is a package maintained by someone whose account could be compromised. The more dependencies you have, the more maintainer accounts, build pipelines, and registries you're trusting.

### Node / npm

```bash
# Total packages in your dependency tree (including transitive)
echo "Direct dependencies:"
node -e "const p=require('./package.json'); console.log(Object.keys(p.dependencies||{}).length + ' production, ' + Object.keys(p.devDependencies||{}).length + ' dev')"

echo "Total packages (including transitive):"
ls node_modules/ 2>/dev/null | wc -l | tr -d ' '

# For a detailed tree:
npm ls --all --parseable 2>/dev/null | wc -l
```

### Python

```bash
# Total installed packages
pip freeze 2>/dev/null | wc -l | tr -d ' '

# What did your project pull in? Compare direct vs total:
echo "Direct dependencies:"
grep -c "." requirements.in 2>/dev/null || grep -c "." requirements.txt 2>/dev/null || echo "unknown"
echo "Total installed:"
pip freeze | wc -l | tr -d ' '
```

**How to interpret:**
- Under 50 transitive dependencies: manageable attack surface
- 50-200: typical for a mid-size project, worth reviewing periodically
- 200-500: large attack surface, consider whether all of these are necessary
- 500+: every install is a significant trust decision - actively look for dependencies you can eliminate or vendor

**To reduce:** Look for heavyweight packages you're using for simple functionality. Can you replace `axios` with Node's built-in `fetch`? Can you replace `lodash` with native array methods? Can you replace `moment` with `Intl.DateTimeFormat`? Every dependency you eliminate is an attack vector you close permanently.

**Verdict:**
- You know your dependency count and have consciously accepted the surface area = PASS
- You've never checked = FAIL

---

## Check 5: Registry and index configuration

Dependency confusion attacks exploit how package managers resolve names when multiple registries are configured. If your pip config uses `--extra-index-url` to point at a private registry, an attacker can publish a package with the same name on public PyPI with a higher version number - and pip will prefer the public one. Similar attacks exist for npm scoped packages.

### Python

```bash
# Check all pip config locations for extra-index-url
echo "=== pip config ==="
pip config list 2>/dev/null | grep -i "index"

echo "=== pip.conf files ==="
for f in /etc/pip.conf ~/.pip/pip.conf ~/.config/pip/pip.conf; do
    [ -f "$f" ] && echo "--- $f ---" && grep -i "index" "$f" 2>/dev/null
done

echo "=== In requirements files ==="
grep -i "extra-index-url\|index-url\|trusted-host" requirements.txt requirements.in 2>/dev/null

echo "=== In pyproject.toml ==="
grep -i "index\|source\|repository" pyproject.toml 2>/dev/null
```

**What you're looking for:**
- `--extra-index-url` is the primary dependency confusion vector. pip checks BOTH the extra index AND public PyPI, and installs whichever has the higher version. An attacker on public PyPI wins by publishing version 99.0.0.
- `--index-url` (replaces PyPI entirely) is safer - pip only checks the one registry you specify.
- `--trusted-host` disables TLS verification for a host. This enables man-in-the-middle attacks on package downloads.

**To fix:** If you use private packages, use `--index-url` (exclusive) rather than `--extra-index-url` (additive). Or use a repository manager (Artifactory, Nexus) as a single index that proxies both private and public packages with policy controls.

### Node / npm

```bash
# Check registry configuration
echo "=== npm registry ==="
npm config get registry

echo "=== .npmrc files ==="
[ -f .npmrc ] && echo "--- project .npmrc ---" && cat .npmrc
[ -f ~/.npmrc ] && echo "--- user .npmrc ---" && cat ~/.npmrc

# Check for auth tokens stored in plaintext
grep -i "_authToken\|_auth\|//.*:_password" .npmrc ~/.npmrc 2>/dev/null && echo "WARNING: auth tokens found in .npmrc files"
```

**What you're looking for:**
- Custom registry URLs: are they over HTTPS? Do you trust them?
- Auth tokens in `.npmrc` files: these are often stored in plaintext. If your machine is compromised, these tokens let the attacker publish packages as you. The TeamPCP campaign specifically harvested CI/CD tokens like these.
- Scoped packages (`@mycompany/foo`) should be configured to resolve from your private registry. Unscoped internal package names are vulnerable to public registry squatting.

**Verdict:**
- No `--extra-index-url`, no plaintext auth tokens, registries are HTTPS = PASS
- `--extra-index-url` present, or plaintext tokens in config files = FAIL

---

## Check 6: Known vulnerabilities in current dependencies

Do any of your current dependencies have known, disclosed security vulnerabilities? This isn't about supply chain attacks specifically (those are zero-day by nature), but about known holes that have patches available.

### Node / npm

```bash
npm audit 2>/dev/null
# Review the output - it lists CVEs, severity, and which package is affected
# Fix automatically where possible:
# npm audit fix
```

### Python

```bash
# pip-audit (install with: pip install pip-audit)
pip-audit 2>/dev/null || echo "pip-audit not installed - run: pip install pip-audit"

# Alternative: safety (install with: pip install safety)
safety check 2>/dev/null || echo "safety not installed - run: pip install safety"
```

**Verdict:**
- Zero critical/high vulnerabilities, or all are acknowledged with a reason = PASS
- Unreviewed vulnerabilities present = FAIL

---

## Quick-run diagnostic

Copy-paste one of these blocks into your terminal from your project's root directory.

### Node / npm project

```bash
echo "====================================="
echo " SUPPLY CHAIN SECURITY DIAGNOSTIC"
echo "====================================="

echo ""
echo "--- 1. LOCKFILE ---"
if [ -f package-lock.json ] || [ -f yarn.lock ] || [ -f pnpm-lock.yaml ]; then
    echo "PASS: lockfile exists"
else
    echo "FAIL: no lockfile found"
fi
git check-ignore package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | head -1 && echo "FAIL: lockfile is gitignored" || echo "PASS: lockfile is tracked"
CI_UNSAFE=$(grep -rn "npm install" .github/ Makefile Dockerfile scripts/ 2>/dev/null | grep -v "npm ci" | grep -v "#" | wc -l | tr -d ' ')
[ "$CI_UNSAFE" -eq 0 ] && echo "PASS: CI uses npm ci" || echo "WARN: $CI_UNSAFE references to 'npm install' in CI/build files (should be 'npm ci')"

echo ""
echo "--- 2. VERSION PINNING ---"
UNPINNED=$(grep -cE '"[\^~><=*]|"latest"' package.json 2>/dev/null || echo 0)
[ "$UNPINNED" -eq 0 ] && echo "PASS: all versions pinned exactly" || echo "FAIL: $UNPINNED dependencies use range specifiers"

echo ""
echo "--- 3. INSTALL SCRIPTS ---"
SCRIPTS_OFF=$(npm config get ignore-scripts 2>/dev/null)
[ "$SCRIPTS_OFF" = "true" ] && echo "PASS: install scripts disabled globally" || echo "FAIL: install scripts enabled (npm default)"
SCRIPTS_PROJECT=$(grep -c "ignore-scripts=true" .npmrc 2>/dev/null || echo 0)
[ "$SCRIPTS_PROJECT" -gt 0 ] && echo "PASS: install scripts disabled in project .npmrc" || echo "INFO: ignore-scripts not set in project .npmrc"
PKGS_WITH_SCRIPTS=$(ls node_modules/*/package.json 2>/dev/null | xargs grep -l '"preinstall"\|"postinstall"' 2>/dev/null | wc -l | tr -d ' ')
echo "INFO: $PKGS_WITH_SCRIPTS packages in node_modules have install scripts"

echo ""
echo "--- 4. ATTACK SURFACE ---"
DIRECT=$(node -e "const p=require('./package.json'); console.log(Object.keys(p.dependencies||{}).length)" 2>/dev/null || echo "?")
TOTAL=$(ls node_modules/ 2>/dev/null | wc -l | tr -d ' ')
echo "INFO: $DIRECT direct dependencies, $TOTAL total packages in node_modules"
[ "$TOTAL" -gt 500 ] && echo "WARN: large attack surface - review whether all dependencies are necessary"

echo ""
echo "--- 5. REGISTRY CONFIG ---"
REGISTRY=$(npm config get registry 2>/dev/null)
echo "INFO: registry = $REGISTRY"
TOKENS=$(grep -c "_authToken\|_auth\|_password" .npmrc ~/.npmrc 2>/dev/null || echo 0)
[ "$TOKENS" -eq 0 ] && echo "PASS: no plaintext auth tokens in .npmrc" || echo "WARN: $TOKENS auth tokens found in .npmrc files"

echo ""
echo "--- 6. KNOWN VULNERABILITIES ---"
AUDIT=$(npm audit --json 2>/dev/null)
if [ $? -eq 0 ]; then
    CRIT=$(echo "$AUDIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('critical',0)+d.get('metadata',{}).get('vulnerabilities',{}).get('high',0))" 2>/dev/null || echo "?")
    [ "$CRIT" = "0" ] && echo "PASS: no critical/high vulnerabilities" || echo "WARN: $CRIT critical/high vulnerabilities found - run 'npm audit' for details"
else
    echo "INFO: run 'npm audit' manually to check"
fi

echo ""
echo "====================================="
```

### Python project

```bash
echo "====================================="
echo " SUPPLY CHAIN SECURITY DIAGNOSTIC"
echo "====================================="

echo ""
echo "--- 1. LOCKFILE ---"
if [ -f requirements.txt ] || [ -f poetry.lock ] || [ -f uv.lock ] || [ -f Pipfile.lock ]; then
    echo "PASS: lockfile exists"
else
    echo "FAIL: no lockfile found"
fi
if [ -f requirements.txt ]; then
    grep -q "\-\-hash=" requirements.txt && echo "PASS: hashes present in requirements.txt" || echo "FAIL: no hashes in requirements.txt (pip cannot verify package integrity)"
fi

echo ""
echo "--- 2. VERSION PINNING ---"
if [ -f requirements.txt ]; then
    UNPINNED=$(grep -vE "^#|^$|^-|==" requirements.txt | grep -cE ">=|~=|<=|!=|[^=><]>[^=]|[^=><]<[^=]|\*" 2>/dev/null || echo 0)
    [ "$UNPINNED" -eq 0 ] && echo "PASS: all versions pinned exactly" || echo "FAIL: $UNPINNED dependencies use range specifiers"
fi
if [ -f pyproject.toml ]; then
    PY_UNPINNED=$(grep -E ">=|~=|<=|!=|\*" pyproject.toml 2>/dev/null | grep -v "python_requires\|requires-python" | wc -l | tr -d ' ')
    [ "$PY_UNPINNED" -eq 0 ] && echo "PASS: pyproject.toml versions pinned" || echo "FAIL: $PY_UNPINNED unpinned dependencies in pyproject.toml"
fi

echo ""
echo "--- 3. CODE EXECUTION ---"
echo "Checking .pth files with executable code:"
python3 -c "
import site, pathlib
count = 0
for d in site.getsitepackages() + [site.getusersitepackages()]:
    p = pathlib.Path(d)
    if p.exists():
        for f in p.glob('*.pth'):
            for line in f.read_text().splitlines():
                if line.strip().startswith('import'):
                    print(f'  {f.name}: {line.strip()}')
                    count += 1
print(f'INFO: {count} .pth files with import statements')
" 2>/dev/null

echo ""
echo "--- 4. ATTACK SURFACE ---"
DIRECT=$(grep -c "." requirements.in 2>/dev/null || grep -cE "^[a-zA-Z]" requirements.txt 2>/dev/null || echo "?")
TOTAL=$(pip freeze 2>/dev/null | wc -l | tr -d ' ')
echo "INFO: ~$DIRECT direct dependencies, $TOTAL total installed packages"
[ "$TOTAL" -gt 200 ] && echo "WARN: large attack surface - review whether all dependencies are necessary"

echo ""
echo "--- 5. REGISTRY CONFIG ---"
EXTRA_IDX=$(pip config list 2>/dev/null | grep -ci "extra-index-url")
[ "$EXTRA_IDX" -eq 0 ] && echo "PASS: no extra-index-url configured (no dependency confusion risk)" || echo "WARN: extra-index-url is configured - dependency confusion risk. Consider using --index-url (exclusive) instead"
TRUSTED=$(pip config list 2>/dev/null | grep -ci "trusted-host")
[ "$TRUSTED" -eq 0 ] && echo "PASS: no trusted-host overrides (TLS verification intact)" || echo "WARN: trusted-host is set - TLS verification disabled for some hosts"

echo ""
echo "--- 6. KNOWN VULNERABILITIES ---"
if command -v pip-audit &>/dev/null; then
    VULNS=$(pip-audit 2>/dev/null | grep -c "FAIL" || echo 0)
    [ "$VULNS" -eq 0 ] && echo "PASS: no known vulnerabilities" || echo "WARN: $VULNS vulnerabilities found - run 'pip-audit' for details"
else
    echo "INFO: pip-audit not installed - run 'pip install pip-audit' then 'pip-audit'"
fi

echo ""
echo "====================================="
```
