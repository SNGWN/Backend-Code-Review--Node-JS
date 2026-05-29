// Patterns that look superficially "sensitive" but are actually safe.
// Every block below MUST produce zero findings under the default report.

// (1) Identifier names containing "key" / "secret" — not credentials.
const STORAGE_KEY = 'user-preferences-v2';
const partitionKey = 'pk-orders';
const keyExtractor = (item: { id: string }) => item.id;
const cacheKeySuffix = 'orders';

// (2) Username / email vars are PII labels but not hardcoded secrets.
const username = 'alice';
const userEmail = 'alice@example.com';
const userId = 12345;

// (3) Common variable named `data` that aliases something untrusted upstream but
// then passes through proper validation. Should not trigger taint sinks on
// unrelated downstream uses of OTHER `data` variables.
function unrelatedFunctionUsingData(): void {
  const data = computeReportRows();
  console.log('processed', data); // unrelated `data`, never tainted
}

function computeReportRows(): number[] {
  return [1, 2, 3];
}

// (4) `setTimeout` with function arg — the SAFE form. Must not trigger code-injection.
function scheduleClose(open: boolean): void {
  if (!open) {
    setTimeout(() => console.log('closing'), 100);
  }
}

// (5) `executeMigration`, `userQuery`, `rawValue` — `query|execute|raw` substring
// false positives the previous regex matcher fired on. Must stay clean.
function executeMigration(name: string): void {
  console.log('migration', name);
}
function userQuery(text: string): string {
  return text.toLowerCase();
}
function rawValue(input: string): string {
  return input.trim();
}

// (6) Utility function whose name STARTS with "delete" but operates on local state.
function deleteCacheKey(localKey: string): void {
  delete (global as unknown as Record<string, unknown>)[localKey];
}

// Reference exports so the file is treated as a module by some TS configs.
export {
  STORAGE_KEY,
  partitionKey,
  keyExtractor,
  cacheKeySuffix,
  username,
  userEmail,
  userId,
  unrelatedFunctionUsingData,
  computeReportRows,
  scheduleClose,
  executeMigration,
  userQuery,
  rawValue,
  deleteCacheKey,
};
