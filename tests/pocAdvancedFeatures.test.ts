import { ExploitChainBuilder } from '../src/poc/ExploitChainBuilder';
import { PocMarkdownReportGenerator } from '../src/poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../src/poc/types';

const buildPoc = (overrides: Partial<ProofOfConcept>): ProofOfConcept => ({
  id: overrides.id || 'poc-1',
  findingId: overrides.findingId || 'AUTHENTICATION-10',
  title: overrides.title || 'Sample Vulnerability',
  description: overrides.description || 'Sample description',
  vulnerabilityType: overrides.vulnerabilityType || 'Hardcoded Secret/Credential',
  severity: overrides.severity || 'CRITICAL',
  cvssScore: overrides.cvssScore,
  steps:
    overrides.steps || [
      {
        stepNumber: 1,
        actor: 'attacker',
        description: 'Control attacker input',
        payload: 'payload',
        expectedResult: 'input accepted',
      },
      {
        stepNumber: 2,
        actor: 'backend',
        description: 'Reach privileged backend path',
        expectedResult: 'backend action executed',
      },
    ],
  codeFlow: overrides.codeFlow || {
    diagram: 'flow',
    components: [],
    connections: [],
  },
  rootCause: overrides.rootCause || 'Missing trust boundary enforcement',
  businessImpact: overrides.businessImpact || 'Sensitive backend workflows can be abused.',
  technicalImpact: overrides.technicalImpact || 'Attackers gain privileged or data-bearing backend access.',
  payloads:
    overrides.payloads || [
      {
        name: 'Reliable payload',
        content: 'payload-1',
        contentType: 'http',
        description: 'Primary exploit payload',
        difficulty: 'easy',
        successRate: 95,
      },
      {
        name: 'Stealth payload',
        content: 'payload-2',
        contentType: 'http',
        description: 'Lower-noise exploit payload',
        difficulty: 'medium',
        successRate: 80,
      },
    ],
  preconditions: overrides.preconditions || ['Attacker can reach the vulnerable endpoint.'],
  remediationDescription: overrides.remediationDescription || 'Patch the vulnerable path and add a regression test.',
  remediationCode: overrides.remediationCode,
  relatedCves: overrides.relatedCves,
  owaspCategory: overrides.owaspCategory,
  generatedAt: overrides.generatedAt || new Date('2026-01-01T00:00:00.000Z'),
  pocVersion: overrides.pocVersion || '2.0',
  exploitInsights: overrides.exploitInsights,
  remediationPlan: overrides.remediationPlan,
});

describe('Advanced POC features', () => {
  test('identifies realistic exploit chains from compatible POCs', () => {
    const pocs = [
      buildPoc({
        id: 'auth-poc',
        findingId: 'AUTHENTICATION-10',
        title: 'Hardcoded Signing Secret',
        vulnerabilityType: 'Hardcoded Secret/Credential',
      }),
      buildPoc({
        id: 'mass-poc',
        findingId: 'MASS_ASSIGNMENT-24',
        title: 'Mass Assignment Role Escalation',
        vulnerabilityType: 'Mass Assignment / Object Pollution',
        severity: 'HIGH',
      }),
      buildPoc({
        id: 'sql-poc',
        findingId: 'VALIDATION-40',
        title: 'SQL Injection in Admin Export',
        vulnerabilityType: 'SQL Injection',
        severity: 'CRITICAL',
      }),
    ];

    const chains = ExploitChainBuilder.identifyExploitChainSummaries(pocs);

    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].linkedPocIds).toEqual(expect.arrayContaining(['auth-poc', 'mass-poc']));
    expect(chains[0].estimatedDamage).toContain('access');
  });

  test('enriches POCs with payload summary and remediation tasks', () => {
    const poc = buildPoc({
      id: 'sql-poc',
      findingId: 'VALIDATION-40',
      title: 'SQL Injection in Reporting Endpoint',
      vulnerabilityType: 'SQL Injection',
    });

    const enriched = ExploitChainBuilder.enrichPoc(poc);

    expect(enriched.exploitInsights?.payloadExecution?.recommendedPayload).toBe('Reliable payload');
    expect(enriched.remediationPlan?.length).toBeGreaterThan(0);
    expect(enriched.remediationPlan?.[0].validationSteps.length).toBeGreaterThan(0);
  });

  test('renders comprehensive reports with chain-aware sections', () => {
    const pocs = [
      buildPoc({
        id: 'auth-poc',
        findingId: 'AUTHENTICATION-10',
        title: 'Hardcoded Signing Secret',
        vulnerabilityType: 'Hardcoded Secret/Credential',
      }),
      buildPoc({
        id: 'mass-poc',
        findingId: 'MASS_ASSIGNMENT-24',
        title: 'Mass Assignment Role Escalation',
        vulnerabilityType: 'Mass Assignment / Object Pollution',
        severity: 'HIGH',
      }),
      buildPoc({
        id: 'sql-poc',
        findingId: 'VALIDATION-40',
        title: 'SQL Injection in Admin Export',
        vulnerabilityType: 'SQL Injection',
        severity: 'CRITICAL',
      }),
    ];

    const report = PocMarkdownReportGenerator.generateComprehensiveReport(pocs, {
      projectName: 'Advanced POC Test',
      analyzedAt: new Date('2026-01-01T00:00:00.000Z'),
      totalVulnerabilities: pocs.length,
      critical: 2,
      high: 1,
      medium: 0,
      low: 0,
    });

    expect(report).toContain('## Confirmed Exploit Chains');
    expect(report).toContain('## Synthesized Chain POCs');
    expect(report).toContain('## Chain-Aware Remediation Roadmap');
    expect(report).toContain('## Payload Reliability');
  });
});
