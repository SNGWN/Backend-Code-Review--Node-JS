import { AnalysisReport, Finding, Severity } from '../types';
import { getRule, listRules, RuleDefinition } from '../rules/registry';
import { normalizePath } from '../rules/fingerprint';

/**
 * SARIF 2.1.0 reporter. Output validates against:
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json
 *
 * What the AppSec engineer gets:
 *   - Stable rule definitions in `tool.driver.rules` keyed by `ruleId` from the registry
 *   - CWE + OWASP taxonomies in `tool.driver.taxa` cross-referenced from each result
 *   - `partialFingerprints` so GitHub code scanning / DefectDojo can dedupe across runs
 *   - SARIF severity mapped from internal severity (CRITICAL/HIGH→error, MEDIUM→warning,
 *     LOW/INFO→note) plus a numeric `security-severity` GitHub uses for filtering
 *   - Suppressed findings emitted with a `suppressions[]` entry so reviewers can see
 *     what was hidden and why
 */

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SEVERITY_TO_LEVEL: Record<Severity, SarifLevel> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
  INFO: 'note',
};

const SEVERITY_TO_SECURITY_SCORE: Record<Severity, string> = {
  CRITICAL: '9.5',
  HIGH: '8.0',
  MEDIUM: '5.5',
  LOW: '3.0',
  INFO: '0.0',
};

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const TOOL_NAME = 'backend-code-review';
const TOOL_VERSION = '1.0.0';
const TOOL_INFORMATION_URI = 'https://github.com/anthropics/backend-code-review';

interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: SarifLevel };
  properties: {
    'security-severity': string;
    tags: string[];
    'problem.severity'?: string;
  };
  relationships?: Array<{
    target: { id: string; toolComponent: { name: string } };
    kinds: string[];
  }>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        startColumn: number;
        snippet?: { text: string };
      };
    };
  }>;
  partialFingerprints: Record<string, string>;
  suppressions?: Array<{ kind: string; justification?: string }>;
  properties?: Record<string, unknown>;
}

export class SarifReporter {
  static build(report: AnalysisReport, options: { includeSuppressed?: boolean } = {}): unknown {
    const rules = listRules().filter((rule) => !rule.deprecated);
    const ruleIndexById = new Map<string, number>();
    rules.forEach((rule, index) => ruleIndexById.set(rule.id, index));

    const allFindings: Finding[] = [...report.findings];
    if (options.includeSuppressed && Array.isArray((report as AnalysisReport & { suppressedFindings?: Finding[] }).suppressedFindings)) {
      allFindings.push(...((report as AnalysisReport & { suppressedFindings?: Finding[] }).suppressedFindings ?? []));
    }

    const results: SarifResult[] = allFindings.map((finding) => SarifReporter.toResult(finding, ruleIndexById));

    const { cweTaxa, owaspTaxa } = SarifReporter.partitionedTaxa();

    return {
      $schema: SARIF_SCHEMA,
      version: SARIF_VERSION,
      runs: [
        {
          tool: {
            driver: {
              name: TOOL_NAME,
              semanticVersion: TOOL_VERSION,
              informationUri: TOOL_INFORMATION_URI,
              rules: rules.map((rule) => SarifReporter.toDescriptor(rule)),
            },
          },
          // SARIF 2.1.0 requires each taxonomy to live in `runs[].taxonomies[]` as a
          // separate `toolComponent` (CWE, OWASP, …). The previous attempt to inline
          // taxa under `driver.taxa[]` with a stray `toolComponent` field on each entry
          // produced 55 schema violations and was rejected by strict ingesters.
          taxonomies: [
            { name: 'CWE', informationUri: 'https://cwe.mitre.org/', taxa: cweTaxa },
            { name: 'OWASP', informationUri: 'https://owasp.org/Top10/', taxa: owaspTaxa },
          ],
          invocations: [
            {
              executionSuccessful: !report.hasRuntimeErrors,
              endTimeUtc: report.timestamp,
            },
          ],
          results,
          columnKind: 'utf16CodeUnits',
        },
      ],
    };
  }

  private static toDescriptor(rule: RuleDefinition): SarifReportingDescriptor {
    const tags = ['security', 'owasp'];
    if (rule.heuristic) tags.push('heuristic');

    const relationships = [
      ...rule.cwe.map((cwe) => ({
        target: { id: cwe, toolComponent: { name: 'CWE' } },
        kinds: ['superset'],
      })),
      ...(rule.owasp ? [{
        target: { id: rule.owasp, toolComponent: { name: 'OWASP' } },
        kinds: ['relevant'],
      }] : []),
    ];

    return {
      id: rule.id,
      name: rule.title.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: rule.title },
      fullDescription: { text: rule.description },
      help: { text: rule.recommendation },
      defaultConfiguration: { level: SEVERITY_TO_LEVEL[rule.defaultSeverity] },
      properties: {
        'security-severity': SEVERITY_TO_SECURITY_SCORE[rule.defaultSeverity],
        tags,
        'problem.severity': rule.defaultSeverity.toLowerCase(),
      },
      relationships,
    };
  }

  private static partitionedTaxa(): { cweTaxa: unknown[]; owaspTaxa: unknown[] } {
    const cweTaxa: unknown[] = [];
    const owaspTaxa: unknown[] = [];
    const cweSeen = new Set<string>();
    const owaspSeen = new Set<string>();
    listRules().forEach((rule) => {
      rule.cwe.forEach((cwe) => {
        if (!cweSeen.has(cwe)) {
          cweSeen.add(cwe);
          cweTaxa.push({ id: cwe, name: cwe });
        }
      });
      if (rule.owasp && !owaspSeen.has(rule.owasp)) {
        owaspSeen.add(rule.owasp);
        owaspTaxa.push({ id: rule.owasp, name: rule.owasp });
      }
    });
    return { cweTaxa, owaspTaxa };
  }

  private static toResult(finding: Finding, ruleIndexById: Map<string, number>): SarifResult {
    const ruleId = finding.ruleId ?? 'BCR-LEGACY';
    const rule = getRule(ruleId);
    const ruleIndex = ruleIndexById.get(ruleId) ?? -1;

    const level: SarifLevel = SEVERITY_TO_LEVEL[finding.severity];

    const result: SarifResult = {
      ruleId,
      ruleIndex,
      level,
      message: { text: `${finding.title}: ${finding.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normalizePath(finding.file) },
            region: {
              startLine: Math.max(1, finding.line),
              startColumn: Math.max(1, finding.column),
              snippet: { text: truncate(finding.code, 200) },
            },
          },
        },
      ],
      partialFingerprints: {
        // `primaryLocationLineHash/v1` is the SARIF-conventional name for "stable hash
        // anchored to the line content"; GitHub code scanning uses it directly for dedup.
        'primaryLocationLineHash/v1': finding.fingerprint ?? '',
      },
      properties: {
        category: finding.category,
        severity: finding.severity,
        cwe: finding.cwe ?? rule?.cwe ?? [],
        owasp: finding.owasp ?? rule?.owasp,
        recommendation: finding.recommendation,
      },
    };

    if (finding.suppressed) {
      result.suppressions = [
        {
          kind: finding.suppressed.source === 'inline' ? 'inSource' : 'external',
          justification: finding.suppressed.reason,
        },
      ];
    }

    return result;
  }
}

function truncate(text: string, length: number): string {
  if (!text) return '';
  if (text.length <= length) return text;
  return text.slice(0, length - 1) + '…';
}
