// Fixture for the "explicit file targets are still analyzable even when gitignored"
// scan-scope test. This file is intentionally listed in the fixture-local .gitignore so
// that broad directory scans skip it, while an explicit file target still analyzes it.
// It is force-added to git (git add -f) because the .gitignore would otherwise exclude it.
export const IGNORED_SECRET_KEY = 'hardcoded-secret-key-67890';

export function ignoredHandler() {
  return IGNORED_SECRET_KEY;
}
