import * as fs from 'fs';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { AuthenticationDetector } from '../src/detectors/authDetector';
import { LogReviewDetector } from '../src/detectors/logDetector';
import { MassAssignmentDetector } from '../src/detectors/massAssignDetector';
import { ParameterValidationDetector } from '../src/detectors/validationDetector';
import { ASTParser } from '../src/parser/astParser';

const fixturesDir = path.join(__dirname, 'fixtures');
const generatedPocDir = path.join(__dirname, 'generated-phase1-pocs');

function cleanupGeneratedPocs(): void {
  if (fs.existsSync(generatedPocDir)) {
    fs.rmSync(generatedPocDir, { recursive: true, force: true });
  }
}

function parseFixture(fixtureName: string) {
  const fixturePath = path.join(fixturesDir, fixtureName);
  const parser = new ASTParser(fixturePath);
  const sourceFile = parser.parse();

  if (!sourceFile) {
    throw new Error(`Failed to parse fixture ${fixtureName}`);
  }

  return { fixturePath, parser, sourceFile };
}

describe('Phase 1 integration/regression coverage', () => {
  afterEach(() => {
    cleanupGeneratedPocs();
  });

  afterAll(() => {
    cleanupGeneratedPocs();
  });

  test('authentication detector generates exploit-ready hardcoded secret POCs', () => {
    const { fixturePath, parser, sourceFile } = parseFixture('vulnerable-auth.ts');
    const detector = new AuthenticationDetector(fixturePath, sourceFile, parser);
    const result = detector.detect();

    const hardcodedSecretFindings = result.findings
      .filter((finding) => finding.title === 'Hardcoded Secret in Variable')
      .map((finding) => finding.line)
      .sort((left, right) => left - right);

    expect(hardcodedSecretFindings).toEqual([6, 7]);

    const generatedPocs = detector.getPocs();
    expect(generatedPocs).toHaveLength(2);
    expect(generatedPocs.every((poc) => poc.vulnerabilityType === 'Hardcoded Secret/Credential')).toBe(true);
    expect(generatedPocs[0].payloads.map((payload) => payload.name)).toEqual(
      expect.arrayContaining(['API Request with Stolen Key', 'Database Connection Exploit'])
    );
    expect(generatedPocs[0].steps[generatedPocs[0].steps.length - 1]?.description).toBe(
      'Exfiltrate Sensitive Data'
    );
    expect(generatedPocs[0].remediationCode).toContain('process.env.JWT_SECRET');
  });

  test('validation detector keeps SQL injection findings tied to concrete POCs', () => {
    const { fixturePath, parser, sourceFile } = parseFixture('vulnerable-validation.ts');
    const detector = new ParameterValidationDetector(fixturePath, sourceFile, parser);
    const result = detector.detect();

    const sqlInjectionFindings = result.findings.filter(
      (finding) => finding.title === 'Unvalidated Input Reaches SQL Query Construction'
    );

    expect(sqlInjectionFindings).toHaveLength(3);

    sqlInjectionFindings.forEach((finding) => {
      expect(finding.severity).toBe('CRITICAL');
      expect(finding.injectionType).toBe('SQL Injection');
      expect(finding.poc).toBeDefined();
      expect(finding.poc?.payloads[0].content).toMatch(/alert\('xss'\)|' OR '1'='1'/);
      expect(finding.poc?.remediationDescription).toContain('parameterized queries');
      expect(finding.poc?.codeFlow?.diagram).toContain('Dangerous Operation');
    });
  });

  test('logging detector preserves high-signal sensitive log and injection findings', () => {
    const { fixturePath, parser, sourceFile } = parseFixture('vulnerable-logging.ts');
    const detector = new LogReviewDetector(fixturePath, sourceFile, parser);
    const result = detector.detect();

    const sensitiveLogFindings = result.findings.filter(
      (finding) => finding.title === 'Sensitive Data in Logs'
    );
    const lowerCaseDescriptions = sensitiveLogFindings.map((finding) =>
      finding.description.toLowerCase()
    );
    const injectionFinding = result.findings.find((finding) => finding.title === 'Log Injection Risk');

    expect(sensitiveLogFindings).toHaveLength(10);
    expect(lowerCaseDescriptions.some((description) => description.includes('password'))).toBe(true);
    expect(lowerCaseDescriptions.some((description) => description.includes('token'))).toBe(true);
    expect(lowerCaseDescriptions.some((description) => description.includes('ssn'))).toBe(true);
    expect(injectionFinding?.severity).toBe('HIGH');
    expect(injectionFinding?.code).toContain('${req.body.query}');
    expect(detector.getPocs()).toHaveLength(0);
  });

  test('mass assignment detector attaches prototype-pollution POCs to exploitable findings', () => {
    const { fixturePath, parser, sourceFile } = parseFixture('vulnerable-mass-assignment.ts');
    const detector = new MassAssignmentDetector(fixturePath, sourceFile, parser);
    const result = detector.detect();

    const prototypePollutionFindings = result.findings.filter(
      (finding) => finding.title === 'Constructor/Prototype Property Assignment'
    );

    expect(prototypePollutionFindings).toHaveLength(2);

    prototypePollutionFindings.forEach((finding) => {
      expect(finding.severity).toBe('CRITICAL');
      expect(finding.poc?.vulnerabilityType).toBe('Mass Assignment / Object Pollution');
      expect(finding.poc?.payloads.map((payload) => payload.name)).toEqual(
        expect.arrayContaining(['Basic Prototype Pollution', 'Constructor Property Injection'])
      );
      expect(finding.poc?.preconditions).toEqual(
        expect.arrayContaining([
          'Attacker can submit data to an endpoint that creates or updates objects',
        ])
      );
      expect(finding.poc?.remediationDescription).toContain('Object.assign()');
    });
  });

  test('analyzer default reporting keeps only exploit-focused rate-limit findings', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const fixturePath = path.join(fixturesDir, 'vulnerable-rate-limit.ts');
    const report = analyzer.analyze(fixturePath);

    const rateLimitTitles = report.findings
      .filter((finding) => finding.category === 'RATE_LIMITING')
      .map((finding) => finding.title);

    expect(rateLimitTitles).toHaveLength(3);
    expect(rateLimitTitles).toEqual(
      expect.arrayContaining([
        'Rate Limit Bypass via Header Manipulation',
        'Weak Rate Limiting on Sensitive Endpoint',
        'Distributed Rate Limit Bypass via Load Balancer',
      ])
    );
    expect(
      rateLimitTitles.some((title) => title.startsWith('Missing Rate Limiting on Sensitive Endpoint'))
    ).toBe(false);
    expect(report.findingsByCategory.RATE_LIMITING).toBe(3);
  });

  test('analyzer exports generated phase 1 POCs as markdown reports', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const fixturePath = path.join(fixturesDir, 'vulnerable-auth.ts');

    analyzer.analyze(fixturePath);

    const generatedPocs = analyzer.getPocs();
    expect(generatedPocs.length).toBeGreaterThanOrEqual(2);

    const exportedFiles = analyzer.exportPocsAsMarkdown(generatedPocDir);
    expect(exportedFiles).toHaveLength(generatedPocs.length);

    const exportedContents = exportedFiles.map((filePath) => fs.readFileSync(filePath, 'utf-8'));
    expect(
      exportedContents.some(
        (content) =>
          content.includes('Hardcoded Secret/Credential') &&
          content.includes('API Request with Stolen Key') &&
          content.includes('## Exploitation Steps')
        )
    ).toBe(true);
  });

  test('analyzer generates one consolidated comprehensive POC report', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const fixturePath = path.join(fixturesDir, 'vulnerable-auth.ts');
    const comprehensiveReportPath = path.join(generatedPocDir, 'comprehensive-report.md');

    analyzer.analyze(fixturePath);

    const reportPath = analyzer.generateComprehensivePocReport(comprehensiveReportPath, 'Phase 1 Fixture');

    expect(reportPath).toBe(comprehensiveReportPath);
    expect(fs.existsSync(reportPath)).toBe(true);

    const reportContents = fs.readFileSync(reportPath, 'utf-8');
    expect(reportContents).toContain('# Security Vulnerability Assessment Report');
    expect(reportContents).toContain('## Detailed Vulnerability Analysis');
    expect(reportContents).toContain('Hardcoded Secret/Credential');
  });
});
