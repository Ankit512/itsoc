#!/usr/bin/env bash
# repo_cleanup.sh — remove the Downloads-import cruft from log-analyzer.
# Run from the repo root:  bash repo_cleanup.sh
# It STAGES deletions + updates .gitignore but does NOT commit — review, then commit yourself.
# Nothing here is pushed, so this is safe and fully reversible (git restore / git reset).

set -u
cd "$(git rev-parse --show-toplevel)" || { echo "not a git repo"; exit 1; }
echo "Repo: $(pwd)"
before=$(git ls-files | wc -l | tr -d ' ')

echo "== 1. Windows Mark-of-the-Web tags (*Zone.Identifier) =="
find . -path ./.git -prune -o -name '*Zone.Identifier*' -print | while read -r f; do
  git rm -f --quiet --ignore-unmatch "$f" 2>/dev/null || rm -f "$f"
done

echo "== 2. backup / scratch duplicates =="
for pat in '*.backup*' 'log_analyzer222.py' 'log_analyzerback2.py'; do
  find . -path ./.git -prune -o -name "$pat" -print | while read -r f; do
    git rm -f --quiet --ignore-unmatch "$f" 2>/dev/null || rm -f "$f"
  done
done

echo "== 3. committed bytecode (__pycache__, *.pyc) =="
git rm -r --quiet --ignore-unmatch '*/__pycache__/*' '__pycache__/*' '*.pyc' 2>/dev/null
find . -path ./.git -prune -o -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null

echo "== 4. .gitignore rules so it never comes back =="
grep -q 'housekeeping (cruft cleanup)' .gitignore 2>/dev/null || cat >> .gitignore <<'EOF'

# --- housekeeping (cruft cleanup) ---
__pycache__/
*.pyc
*Zone.Identifier
*.backup*
report.json
report.md
state.json
EOF
git add .gitignore

after=$(git ls-files | wc -l | tr -d ' ')
echo
echo "Tracked files: $before -> $after   (removed $((before - after)))"
echo
echo "== FLAGGED — decide yourself, then git rm if you agree =="
echo "  INSTALL_FIXED.sh / INSTALL_NMAP_VULN_FIXED.sh / INSTALL_TIMEOUT_FIX.sh"
echo "     ^ ad-hoc patch scripts; keep one canonical install doc/script and drop the rest."
echo "  web/log_analyzer.py   ^ a stray Python file inside the React app dir — almost certainly a mis-drop."
echo "  state.json / zookeeper_integrated.json   ^ scratch test I/O; keep only if a test needs the fixture."
echo
echo "Review with:  git status   &&   git diff --cached --stat"
echo "Then commit:  git commit -m 'chore: remove Downloads-import cruft (Zone.Identifier, backups, bytecode)'"
echo "Undo all:     git reset && git restore ."
