// Barrel file re-exporting a dangerous Node API. Cross-file resolution must
// follow `./a` → 'child_process' and treat `runShell` as `exec`.
export { exec as runShell } from 'child_process';
