import {
  ProofOfConcept,
  ExploitationStep,
  CodeFlow,
  FlowComponent,
  FlowConnection,
  Payload,
  PocGeneratorConfig,
  PocGenerationRequest,
  PocGenerationResult,
} from './types';

type ExploitationActor = ExploitationStep['actor'];
type FlowComponentOptions = Omit<Partial<FlowComponent>, 'id' | 'name' | 'type'>;
type FlowConnectionOptions = Omit<Partial<FlowConnection>, 'from' | 'to'>;
type PayloadOptions = Omit<Partial<Payload>, 'name' | 'content' | 'contentType' | 'description'>;

/**
 * Base POC Generator
 *
 * This class provides the foundation for generating Proof-of-Concept documents
 * for vulnerabilities. Each vulnerability detector extends this class to create
 * specialized POCs with step-by-step exploitation flows and code navigation.
 */
export abstract class PocGenerator {
  /**
   * Configuration for POC generation
   */
  protected config: PocGeneratorConfig;

  /**
   * Initialize POC Generator with configuration
   */
  constructor(config: Partial<PocGeneratorConfig> = {}) {
    this.config = {
      includeCodeSnippets: true,
      includePayloads: true,
      includeCodeFlow: true,
      includeRemediation: true,
      verbosity: 'normal',
      format: 'markdown',
      generateDiagrams: true,
      ...config,
    };
  }

  /**
   * Generate a complete POC from a security finding
   * Subclasses should override this to provide specific POC generation logic
   */
  abstract generate(request: PocGenerationRequest): PocGenerationResult;

  /**
   * Create a step in the exploitation flow
   * Helper method for building exploitation steps
   */
  protected createStep(
    stepNumber: number,
    description: string,
    actor: ExploitationActor,
    options: Partial<ExploitationStep> = {}
  ): ExploitationStep {
    return {
      stepNumber,
      description,
      actor,
      ...options,
    };
  }

  /**
   * Create a code flow component
   */
  protected createFlowComponent(
    id: string,
    name: string,
    type: 'input' | 'validation' | 'processing' | 'storage' | 'output' | 'vulnerable' | 'protection',
    options: FlowComponentOptions = {}
  ): FlowComponent {
    return {
      id,
      name,
      type,
      ...options,
    };
  }

  /**
   * Create a code flow connection
   */
  protected createFlowConnection(
    from: string,
    to: string,
    options: FlowConnectionOptions = {}
  ): FlowConnection {
    return {
      from,
      to,
      ...options,
    };
  }

  /**
   * Create an attack payload
   */
  protected createPayload(
    name: string,
    content: string,
    contentType: string,
    description: string,
    options: PayloadOptions = {}
  ): Payload {
    return {
      name,
      content,
      contentType,
      description,
      ...options,
    };
  }

  /**
   * Build a basic code flow for request → vulnerable code → response pattern
   */
  protected buildBasicRequestResponseFlow(
    vulnerableComponent: string,
    vulnerableFile: string,
    vulnerableLine: number
  ): CodeFlow {
    const components = [
      this.createFlowComponent('input', 'User Input/Request', 'input', {
        description: 'Attacker-controlled input',
      }),
      this.createFlowComponent('processing', 'Request Parsing', 'processing', {
        description: 'Parse request parameters, body, headers',
      }),
      this.createFlowComponent('vulnerable', vulnerableComponent, 'vulnerable', {
        location: `${vulnerableFile}:${vulnerableLine}`,
        isVulnerable: true,
        description: 'Vulnerable code execution',
      }),
      this.createFlowComponent('output', 'Response', 'output', {
        description: 'Application response to attacker',
      }),
    ];

    const connections = [
      this.createFlowConnection('input', 'processing', {
        label: 'HTTP request',
        isVulnerable: true,
      }),
      this.createFlowConnection('processing', 'vulnerable', {
        label: 'unsanitized input',
        isVulnerable: true,
      }),
      this.createFlowConnection('vulnerable', 'output', {
        label: 'response data',
      }),
    ];

    const diagram = this.generateBasicDiagram(components, connections);

    return {
      diagram,
      components,
      connections,
    };
  }

  /**
   * Generate ASCII diagram from components and connections
   */
  protected generateBasicDiagram(components: FlowComponent[], connections: FlowConnection[]): string {
    const lines: string[] = [];

    // Find input -> processing -> vulnerable -> output chain
    const input = components.find((c) => c.type === 'input');
    const processing = components.find((c) => c.type === 'processing');
    const vulnerable = components.find((c) => c.type === 'vulnerable');
    const output = components.find((c) => c.type === 'output');

    if (input && processing && vulnerable && output) {
      lines.push(`┌─────────────────────────────────────────────────────────┐`);
      lines.push(`│ Exploitation Flow Diagram                              │`);
      lines.push(`└─────────────────────────────────────────────────────────┘`);
      lines.push(``);
      lines.push(`  [1] Attacker Input`);
      lines.push(`       ↓`);
      lines.push(`  [2] Request Processing`);
      lines.push(`       ↓`);
      lines.push(`  [3] ⚠️  VULNERABLE CODE (${vulnerable.location})`);
      lines.push(`       ↓`);
      lines.push(`  [4] Response to Attacker`);
      lines.push(``);
    }

    return lines.join('\n');
  }

  /**
   * Generate a basic POC template (used by subclasses)
   */
  protected createBasePoc(
    id: string,
    title: string,
    vulnerabilityType: string,
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    request: PocGenerationRequest
  ): ProofOfConcept {
    return {
      id,
      findingId: request.finding?.category
        ? `${request.finding.category}-${request.location.line}`
        : undefined,
      title,
      description: '',
      vulnerabilityType,
      severity,
      steps: [],
      codeFlow: {
        diagram: '',
        components: [],
        connections: [],
      },
      rootCause: '',
      businessImpact: '',
      technicalImpact: '',
      payloads: [] as Payload[],
      remediationDescription: '',
      generatedAt: new Date(),
      pocVersion: '1.0',
    };
  }

  /**
   * Format code snippet with line numbers
   */
  protected formatCodeSnippet(code: string, startLine: number, highlight: number[] = []): string {
    const lines = code.split('\n');
    const formatted: string[] = [];

    lines.forEach((line, idx) => {
      const lineNum = startLine + idx;
      const isHighlight = highlight.includes(lineNum);
      const marker = isHighlight ? '>>> ' : '    ';
      formatted.push(`${marker}${String(lineNum).padStart(3, ' ')} | ${line}`);
    });

    return formatted.join('\n');
  }

  /**
   * Generate step diagram showing numbered sequence
   */
  protected generateStepDiagram(steps: ExploitationStep[]): string {
    const lines: string[] = [];
    lines.push(`Step-by-Step Exploitation:`);
    lines.push(``);

    steps.forEach((step, idx) => {
      lines.push(`[Step ${step.stepNumber}] ${step.description}`);
      if (step.actor) {
        lines.push(`           Actor: ${step.actor}`);
      }
      if (step.payload) {
        lines.push(`           Payload: ${step.payload.substring(0, 60)}${step.payload.length > 60 ? '...' : ''}`);
      }
      if (idx < steps.length - 1) {
        lines.push(`             ↓`);
      }
      lines.push(``);
    });

    return lines.join('\n');
  }

  /**
   * Get severity color/badge for reports
   */
  protected getSeverityBadge(severity: string): string {
    const badges: { [key: string]: string } = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🟢',
      INFO: '🔵',
    };
    return badges[severity] || '⚪';
  }

  /**
   * Common remediation template
   */
  protected getRemediationTemplate(vulnerabilityType: string): string {
    const templates: { [key: string]: string } = {
      'hardcoded-secret': `// ❌ VULNERABLE: Hardcoded secret
const API_KEY = 'sk-xxxxxxxxxxxxx';

// ✅ FIXED: Use environment variables
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
  throw new Error('API_KEY environment variable is required');
}`,

      'sql-injection': `// ❌ VULNERABLE: Direct SQL concatenation
const query = \`SELECT * FROM users WHERE id = \${req.params.id}\`;
db.query(query);

// ✅ FIXED: Use parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [req.params.id]);`,

      'unvalidated-input': `// ❌ VULNERABLE: Direct usage of user input
const email = req.body.email;
await db.createUser(email);

// ✅ FIXED: Validate input first
const schema = Joi.object({
  email: Joi.string().email().required(),
});
const { error, value } = schema.validate(req.body);
if (error) throw new Error(error.details[0].message);
await db.createUser(value.email);`,

      'missing-auth': `// ❌ VULNERABLE: No authentication check
app.delete('/api/users/:id', (req, res) => {
  db.deleteUser(req.params.id);
});

// ✅ FIXED: Add authentication middleware
app.delete('/api/users/:id', authenticate, (req, res) => {
  db.deleteUser(req.params.id);
});`,
    };

    return templates[vulnerabilityType] || '// See detailed remediation steps above';
  }
}
