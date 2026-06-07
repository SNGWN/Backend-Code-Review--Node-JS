import { ProofOfConcept, Payload, RemediationTask, ExploitChainSummary } from './types';
import { ExploitChainBuilder } from './ExploitChainBuilder';
import * as fs from 'fs';
import * as path from 'path';

interface PocReportSummary {
  projectName?: string;
  analyzedAt: Date;
  totalVulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * Markdown POC Report Generator
 *
 * Converts ProofOfConcept objects into exploit-focused Markdown reports with
 * chain-aware context, payload reliability, and remediation priorities.
 */
export class PocMarkdownReportGenerator {
  /**
   * Emit a fenced code block whose fence is longer than any backtick run inside the content, so
   * scanned source containing ``` cannot break out of the fence and inject arbitrary
   * markdown/HTML into the report. Returns the lines to push.
   */
  private static codeBlock(content: string, lang = ''): string[] {
    const text = content ?? '';
    const runs: string[] = text.match(/`+/g) ?? [];
    const longestRun = runs.reduce((max: number, run: string) => Math.max(max, run.length), 0);
    const fence = '`'.repeat(Math.max(3, longestRun + 1));
    return [`${fence}${lang}`, text, fence];
  }

  /** Neutralise HTML in finding-derived strings rendered into raw-HTML table cells. */
  private static escapeHtml(value: string): string {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  static generatePocMarkdown(poc: ProofOfConcept, relatedPocs: ProofOfConcept[] = []): string {
    const enriched = ExploitChainBuilder.enrichPoc(poc, relatedPocs);
    const sections: string[] = [];
    const badge = this.getSeverityBadge(enriched.severity);

    sections.push(`# ${badge} ${enriched.title}`);
    sections.push('');
    sections.push(this.generateInfoBox(enriched));
    sections.push('## Overview');
    sections.push('');
    sections.push(enriched.description);
    sections.push('');
    sections.push('## Exploitability Snapshot');
    sections.push('');
    sections.push(this.generateExploitabilitySnapshot(enriched));
    sections.push('');
    sections.push('## Root Cause');
    sections.push('');
    sections.push(enriched.rootCause);
    sections.push('');

    if (enriched.codeFlow?.diagram) {
      sections.push('## Code Execution Flow');
      sections.push('');
      sections.push(...this.codeBlock(enriched.codeFlow.diagram));
      sections.push('');
    }

    sections.push('## Exploitation Steps');
    sections.push('');
    sections.push(this.generateStepsMarkdown(enriched.steps));
    sections.push('');

    if (enriched.payloads.length > 0) {
      sections.push('## Attack Payloads');
      sections.push('');
      sections.push(this.generatePayloadsMarkdown(enriched.payloads));
      sections.push('');
      sections.push('## Payload Reliability');
      sections.push('');
      sections.push(this.generatePayloadSummary(enriched.payloads));
      sections.push('');
    }

    if (enriched.preconditions?.length) {
      sections.push('## Attack Preconditions');
      sections.push('');
      enriched.preconditions.forEach((condition) => sections.push(`- ${condition}`));
      sections.push('');
    }

    if (enriched.exploitInsights?.chainOpportunities?.length) {
      sections.push('## Confirmed Chain Opportunities');
      sections.push('');
      sections.push(this.generateChainOpportunitiesMarkdown(enriched.exploitInsights.chainOpportunities));
      sections.push('');
    }

    sections.push('## Impact Analysis');
    sections.push('');
    sections.push('### Business Impact');
    sections.push('');
    sections.push(enriched.businessImpact);
    sections.push('');
    sections.push('### Technical Impact');
    sections.push('');
    sections.push(enriched.technicalImpact);
    sections.push('');

    if (enriched.stepsToReproduce?.length) {
      sections.push('## Steps to Reproduce Locally');
      sections.push('');
      enriched.stepsToReproduce.forEach((step, idx) => sections.push(`${idx + 1}. ${step}`));
      sections.push('');
    }

    sections.push('## Remediation');
    sections.push('');
    sections.push(enriched.remediationDescription);
    sections.push('');

    if (enriched.remediationPlan?.length) {
      sections.push('### Prioritized Remediation Tasks');
      sections.push('');
      sections.push(this.generateRemediationPlanMarkdown(enriched.remediationPlan));
      sections.push('');
    }

    if (enriched.remediationCode) {
      sections.push('### Fixed Code Example');
      sections.push('');
      sections.push(...this.codeBlock(enriched.remediationCode, 'typescript'));
      sections.push('');
    }

    sections.push('## References & Standards');
    sections.push('');
    if (enriched.owaspCategory) {
      sections.push(`- **OWASP Category**: ${enriched.owaspCategory}`);
    }
    if (enriched.relatedCves?.length) {
      sections.push(`- **Related CVEs**: ${enriched.relatedCves.join(', ')}`);
    }
    if (enriched.cvssScore) {
      sections.push(`- **CVSS Score (estimated)**: ${enriched.cvssScore}`);
    }
    sections.push('');
    sections.push('---');
    sections.push('');
    sections.push(`*POC Generated: ${enriched.generatedAt.toISOString()}*`);
    sections.push(`*Version: ${enriched.pocVersion}*`);

    return sections.join('\n');
  }

  static generateComprehensiveReport(pocs: ProofOfConcept[], summary: PocReportSummary): string {
    const enrichedPocs = pocs.map((poc) =>
      ExploitChainBuilder.enrichPoc(
        poc,
        pocs.filter((candidate) => candidate.id !== poc.id)
      )
    );
    const chainSummaries = ExploitChainBuilder.identifyExploitChainSummaries(enrichedPocs);
    const chainPocs = chainSummaries.map((chain) =>
      ExploitChainBuilder.buildExploitChain(
        chain.title,
        enrichedPocs.filter((poc) => chain.linkedPocIds.includes(poc.id))
      )
    );
    const lines: string[] = [];

    lines.push('# Security Vulnerability Assessment Report');
    lines.push('');
    if (summary.projectName) {
      lines.push(`**Project**: ${summary.projectName}`);
    }
    lines.push(`**Generated**: ${summary.analyzedAt.toISOString()}`);
    lines.push('');
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(
      `This exploit-focused report documents ${summary.totalVulnerabilities} vulnerabilities with proof-of-concept detail centered on reachable backend abuse paths.`
    );
    lines.push('');
    lines.push('## Risk Summary');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    lines.push(`| 🔴 CRITICAL | ${summary.critical} |`);
    lines.push(`| 🟠 HIGH | ${summary.high} |`);
    lines.push(`| 🟡 MEDIUM | ${summary.medium} |`);
    lines.push(`| 🟢 LOW | ${summary.low} |`);
    lines.push('');

    if (chainSummaries.length > 0) {
      lines.push('## Confirmed Exploit Chains');
      lines.push('');
      chainSummaries.forEach((chain, index) => {
        lines.push(`### ${index + 1}. ${chain.title}`);
        lines.push('');
        lines.push(chain.narrative);
        lines.push('');
        lines.push(`- **Attack Path**: ${chain.attackPath.join(' → ')}`);
        lines.push(`- **Risk Multiplier**: x${chain.riskMultiplier}`);
        lines.push(`- **Estimated Damage**: ${chain.estimatedDamage}`);
        lines.push(`- **Breakpoints**: ${chain.breakpoints.join(' | ')}`);
        lines.push('');
      });
    }

    lines.push('## Vulnerability Details');
    lines.push('');
    enrichedPocs.forEach((poc, idx) => {
      lines.push(`### ${idx + 1}. ${poc.title}`);
      lines.push(`**Severity**: ${poc.severity} | **Type**: ${poc.vulnerabilityType}`);
      lines.push(`**Finding ID**: ${poc.findingId || 'N/A'}`);
      lines.push('');
      lines.push(`[👉 View Full Details](#pocdetail-${idx})`);
      lines.push('');
    });

    if (chainPocs.length > 0) {
      lines.push('## Synthesized Chain POCs');
      lines.push('');
      chainPocs.forEach((chainPoc, idx) => {
        lines.push(`### Chain ${idx + 1}: ${chainPoc.title}`);
        lines.push(`- **Outcome**: ${chainPoc.exploitInsights?.likelyOutcome || chainPoc.businessImpact}`);
        lines.push(
          `- **Recommended Breakpoint**: ${chainPoc.remediationPlan?.[0]?.actions?.[0] || 'Patch the earliest foothold'}`
        );
        lines.push('');
      });
    }

    lines.push('---');
    lines.push('');
    lines.push('## Detailed Vulnerability Analysis');
    lines.push('');
    enrichedPocs.forEach((poc, idx) => {
      lines.push(`<a name="pocdetail-${idx}"></a>`);
      lines.push('');
      lines.push(this.generatePocMarkdown(poc, enrichedPocs.filter((candidate) => candidate.id !== poc.id)));
      lines.push('');
      lines.push('---');
      lines.push('');
    });

    if (chainPocs.length > 0) {
      lines.push('## Detailed Exploit Chains');
      lines.push('');
      chainPocs.forEach((chainPoc, idx) => {
        lines.push(`<a name="chainpoc-${idx}"></a>`);
        lines.push('');
        lines.push(this.generatePocMarkdown(chainPoc, chainPocs.filter((_, chainIndex) => chainIndex !== idx)));
        lines.push('');
        lines.push('---');
        lines.push('');
      });
    }

    lines.push('## Chain-Aware Remediation Roadmap');
    lines.push('');
    lines.push(this.generateRoadmap(enrichedPocs, chainSummaries));
    lines.push('');
    lines.push('## Statistics');
    lines.push('');
    lines.push(`- **Total Vulnerabilities**: ${summary.totalVulnerabilities}`);
    lines.push(`- **Critical**: ${summary.critical} (${this.getPercentage(summary.critical, summary.totalVulnerabilities)}%)`);
    lines.push(`- **High**: ${summary.high} (${this.getPercentage(summary.high, summary.totalVulnerabilities)}%)`);
    lines.push(`- **Medium**: ${summary.medium} (${this.getPercentage(summary.medium, summary.totalVulnerabilities)}%)`);
    lines.push(`- **Low**: ${summary.low} (${this.getPercentage(summary.low, summary.totalVulnerabilities)}%)`);
    lines.push(`- **Confirmed Exploit Chains**: ${chainSummaries.length}`);
    lines.push('');

    return lines.join('\n');
  }

  static savePocReport(poc: ProofOfConcept, outputDir: string): string {
    const markdown = this.generatePocMarkdown(poc);
    const fileName = `${poc.id}.md`;
    const filePath = path.join(outputDir, fileName);

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(filePath, markdown, 'utf-8');
    return filePath;
  }

  static saveComprehensiveReport(pocs: ProofOfConcept[], summary: PocReportSummary, outputPath: string): string {
    const markdown = this.generateComprehensiveReport(pocs, summary);
    fs.writeFileSync(outputPath, markdown, 'utf-8');
    return outputPath;
  }

  private static generateInfoBox(poc: ProofOfConcept): string {
    const payloadSummary = poc.exploitInsights?.payloadExecution;
    const difficulty = payloadSummary?.easiestDifficulty || 'medium';

    const esc = PocMarkdownReportGenerator.escapeHtml;
    return [
      '<table>',
      '<tr><td><strong>Vulnerability Type</strong></td><td>' + esc(poc.vulnerabilityType) + '</td></tr>',
      '<tr><td><strong>Severity</strong></td><td>' + esc(poc.severity) + '</td></tr>',
      '<tr><td><strong>Attack Complexity</strong></td><td>' + esc(poc.exploitInsights?.attackComplexity || 'medium') + '</td></tr>',
      '<tr><td><strong>Easiest Payload</strong></td><td>' + esc(difficulty) + '</td></tr>',
      '<tr><td><strong>Chainable</strong></td><td>' + ((poc.exploitInsights?.chainOpportunities?.length || 0) > 0 ? 'yes' : 'no') + '</td></tr>',
      '</table>',
    ].join('\n');
  }

  private static generateExploitabilitySnapshot(poc: ProofOfConcept): string {
    const payloadSummary = poc.exploitInsights?.payloadExecution;
    const lines = [
      `- **Likely Outcome**: ${poc.exploitInsights?.likelyOutcome || poc.technicalImpact}`,
      `- **Recommended Payload**: ${poc.exploitInsights?.recommendedPayload || 'See payload list below'}`,
    ];

    if (payloadSummary) {
      lines.push(`- **Reliable Payloads**: ${payloadSummary.reliablePayloadCount}/${payloadSummary.totalPayloads}`);
      if (typeof payloadSummary.averageSuccessRate === 'number') {
        lines.push(`- **Estimated Reliability (heuristic)**: ${payloadSummary.averageSuccessRate}%`);
      }
    }

    return lines.join('\n');
  }

  private static generateStepsMarkdown(steps: ProofOfConcept['steps']): string {
    const lines: string[] = [];

    steps.forEach((step) => {
      lines.push(`### Step ${step.stepNumber}: ${step.description}`);
      lines.push('');
      lines.push(`- **Actor**: ${step.actor}`);
      if (step.actionType) {
        lines.push(`- **Action**: ${step.actionType}`);
      }
      if (step.filePath && step.lineNumber) {
        lines.push(`- **Location**: \`${step.filePath}:${step.lineNumber}\``);
      }
      if (step.expectedResult) {
        lines.push(`- **Expected Result**: ${step.expectedResult}`);
      }
      if (step.notes) {
        lines.push(`- **Notes**: ${step.notes}`);
      }
      lines.push('');

      if (step.codeSnippet) {
        lines.push(...this.codeBlock(step.codeSnippet, 'javascript'));
        lines.push('');
      }

      if (step.payload) {
        lines.push(...this.codeBlock(step.payload));
        lines.push('');
      }
    });

    return lines.join('\n');
  }

  private static generatePayloadsMarkdown(payloads: Payload[]): string {
    const lines: string[] = [];

    payloads.forEach((payload, idx) => {
      lines.push(`### Payload ${idx + 1}: ${payload.name}`);
      lines.push('');
      lines.push(payload.description);
      lines.push('');
      lines.push(`- **Content Type**: \`${payload.contentType}\``);
      if (payload.difficulty) {
        lines.push(`- **Difficulty**: ${payload.difficulty}`);
      }
      if (typeof payload.successRate === 'number') {
        lines.push(`- **Estimated Reliability (heuristic, not measured)**: ${payload.successRate}%`);
      }
      if (payload.expectedOutput) {
        lines.push(`- **Expected Output**: ${payload.expectedOutput}`);
      }
      lines.push('');
      lines.push(...this.codeBlock(payload.content, payload.contentType));
      lines.push('');
    });

    return lines.join('\n');
  }

  private static generatePayloadSummary(payloads: Payload[]): string {
    const summary = ExploitChainBuilder.summarizePayloads(payloads);
    return [
      '| Metric | Value |',
      '|--------|-------|',
      `| Total payloads | ${summary.totalPayloads} |`,
      `| Reliable payloads (>=80%) | ${summary.reliablePayloadCount} |`,
      `| Recommended payload | ${summary.recommendedPayload || 'N/A'} |`,
      `| Easiest difficulty | ${summary.easiestDifficulty || 'N/A'} |`,
      `| Average success rate | ${typeof summary.averageSuccessRate === 'number' ? `${summary.averageSuccessRate}%` : 'N/A'} |`,
    ].join('\n');
  }

  private static generateChainOpportunitiesMarkdown(chains: ExploitChainSummary[]): string {
    const lines: string[] = [];

    chains.forEach((chain, index) => {
      lines.push(`### Chain ${index + 1}: ${chain.title}`);
      lines.push('');
      lines.push(chain.narrative);
      lines.push('');
      lines.push(`- **Attack Path**: ${chain.attackPath.join(' → ')}`);
      lines.push(`- **Estimated Damage**: ${chain.estimatedDamage}`);
      lines.push(`- **Breakpoints**: ${chain.breakpoints.join(' | ')}`);
      lines.push('');
    });

    return lines.join('\n');
  }

  private static generateRemediationPlanMarkdown(tasks: RemediationTask[]): string {
    const lines: string[] = [];

    tasks.forEach((task, index) => {
      lines.push(`#### ${index + 1}. ${task.title} (${task.priority})`);
      lines.push('');
      lines.push(`- **Why**: ${task.rationale}`);
      lines.push(`- **Blocks exploit chain**: ${task.blocksExploitChain ? 'yes' : 'no'}`);
      lines.push('- **Actions**:');
      task.actions.forEach((action) => lines.push(`  - ${action}`));
      lines.push('- **Validation**:');
      task.validationSteps.forEach((step) => lines.push(`  - ${step}`));
      lines.push('');
    });

    return lines.join('\n');
  }

  private static generateRoadmap(pocs: ProofOfConcept[], chains: ExploitChainSummary[]): string {
    const lines: string[] = [];
    const immediate = new Set<string>();
    const high = new Set<string>();
    const medium = new Set<string>();

    chains.forEach((chain) => chain.breakpoints.forEach((breakpoint) => immediate.add(breakpoint)));
    pocs.forEach((poc) => {
      (poc.remediationPlan || []).forEach((task) => {
        const bucket = task.priority === 'immediate' ? immediate : task.priority === 'high' ? high : medium;
        bucket.add(`${task.title}: ${task.actions[0]}`);
      });
    });

    lines.push('### Immediate');
    lines.push('');
    [...immediate].forEach((item) => lines.push(`- [ ] ${item}`));
    lines.push('');
    lines.push('### High');
    lines.push('');
    [...high].forEach((item) => lines.push(`- [ ] ${item}`));
    lines.push('');
    lines.push('### Medium');
    lines.push('');
    [...medium].forEach((item) => lines.push(`- [ ] ${item}`));

    return lines.join('\n');
  }

  private static getPercentage(count: number, total: number): string {
    if (total === 0) {
      return '0.0';
    }

    return ((count / total) * 100).toFixed(1);
  }

  private static getSeverityBadge(severity: string): string {
    const badges: Record<string, string> = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🟢',
      INFO: '🔵',
    };

    return badges[severity] || '⚪';
  }
}
