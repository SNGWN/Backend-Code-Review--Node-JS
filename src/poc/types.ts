import type { Finding } from '../types';

/**
 * POC (Proof of Concept) Type Definitions
 *
 * This file defines the complete structure for generating, storing, and
 * rendering exploitable vulnerabilities with step-by-step exploitation flows
 * and code navigation information.
 */

/**
 * Represents a single step in the exploitation process
 */
export interface ExploitationStep {
  /**
   * Step number (1, 2, 3, etc.)
   */
  stepNumber: number;

  /**
   * Brief description of what happens in this step
   */
  description: string;

  /**
   * Code snippet related to this step (vulnerable code, exploit code, or trigger)
   */
  codeSnippet?: string;

  /**
   * File path where vulnerable code is located
   */
  filePath?: string;

  /**
   * Line number in the file
   */
  lineNumber?: number;

  /**
   * Actor/component involved (frontend, backend service, attacker, database, etc.)
   */
  actor: 'attacker' | 'frontend' | 'backend' | 'service' | 'database' | 'cache' | 'queue' | 'external';

  /**
   * Optional payload for this step
   */
  payload?: string;

  /**
   * Expected result/response from this step
   */
  expectedResult?: string;

  /**
   * Type of action (request, response, query, mutation, etc.)
   */
  actionType?: string;

  /**
   * Additional notes or context
   */
  notes?: string;
}

/**
 * Represents the code flow visualization
 */
export interface CodeFlow {
  /**
   * ASCII or text-based diagram showing the vulnerable code path
   */
  diagram: string;

  /**
   * Components involved in the flow
   */
  components: FlowComponent[];

  /**
   * Connections between components showing data/control flow
   */
  connections: FlowConnection[];
}

/**
 * A component in the code flow diagram
 */
export interface FlowComponent {
  /**
   * Unique identifier for this component
   */
  id: string;

  /**
   * Human-readable name
   */
  name: string;

  /**
   * File and line reference
   */
  location?: string;

  /**
   * Component type
   */
  type: 'input' | 'validation' | 'processing' | 'storage' | 'output' | 'vulnerable' | 'protection';

  /**
   * Description of what this component does
   */
  description?: string;

  /**
   * Whether this component is vulnerable
   */
  isVulnerable?: boolean;
}

/**
 * Connection between components in code flow
 */
export interface FlowConnection {
  /**
   * ID of source component
   */
  from: string;

  /**
   * ID of target component
   */
  to: string;

  /**
   * Data/value flowing through this connection
   */
  data?: string;

  /**
   * Connection label
   */
  label?: string;

  /**
   * Whether this connection is part of vulnerable path
   */
  isVulnerable?: boolean;
}

export interface PayloadExecutionSummary {
  totalPayloads: number;
  averageSuccessRate?: number;
  easiestDifficulty?: 'easy' | 'medium' | 'hard';
  recommendedPayload?: string;
  reliablePayloadCount: number;
}

export interface RemediationTask {
  title: string;
  priority: 'immediate' | 'high' | 'medium';
  rationale: string;
  actions: string[];
  validationSteps: string[];
  blocksExploitChain?: boolean;
}

export interface ExploitChainSummary {
  id: string;
  title: string;
  narrative: string;
  linkedPocIds: string[];
  attackPath: string[];
  prerequisites: string[];
  riskMultiplier: number;
  estimatedDamage: string;
  breakpoints: string[];
}

export interface ExploitInsights {
  attackComplexity: 'low' | 'medium' | 'high';
  likelyOutcome: string;
  recommendedPayload?: string;
  payloadExecution?: PayloadExecutionSummary;
  chainOpportunities?: ExploitChainSummary[];
}

/**
 * Complete Proof of Concept for a vulnerability
 */
export interface ProofOfConcept {
  /**
   * Unique identifier for this POC
   */
  id: string;

  /**
   * Finding ID this POC is associated with
   */
  findingId?: string;

  /**
   * Vulnerability title
   */
  title: string;

  /**
   * Detailed description of the vulnerability
   */
  description: string;

  /**
   * Vulnerability type/category
   */
  vulnerabilityType: string;

  /**
   * Severity level
   */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

  /**
   * CVSS score if applicable
   */
  cvssScore?: number;

  /**
   * Step-by-step exploitation process
   */
  steps: ExploitationStep[];

  /**
   * Code flow visualization
   */
  codeFlow: CodeFlow;

  /**
   * Root cause of the vulnerability
   */
  rootCause: string;

  /**
   * Business impact if exploited
   */
  businessImpact: string;

  /**
   * Technical impact if exploited
   */
  technicalImpact: string;

  /**
   * Example attack payloads
   */
  payloads: Payload[];

  /**
   * Attack preconditions/requirements
   */
  preconditions?: string[];

  /**
   * Steps to reproduce (for manual testing)
   */
  stepsToReproduce?: string[];

  /**
   * Recommended fix
   */
  remediationCode?: string;

  /**
   * Remediation description
   */
  remediationDescription: string;

  /**
   * Related CVEs if applicable
   */
  relatedCves?: string[];

  /**
   * OWASP Top 10 category
   */
  owaspCategory?: string;

  /**
   * Timestamp when POC was generated
   */
  generatedAt: Date;

  /**
   * Version of POC format
   */
  pocVersion: '1.0' | '2.0';

  /**
   * Derived exploitability metadata for higher-signal reporting
   */
  exploitInsights?: ExploitInsights;

  /**
   * Prioritized remediation tasks for this exploit path
   */
  remediationPlan?: RemediationTask[];
}

/**
 * Attack payload example
 */
export interface Payload {
  /**
   * Human-readable name/description
   */
  name: string;

  /**
   * The actual payload/exploit code
   */
  content: string;

  /**
   * Content type (sql, javascript, json, xml, http, bash, etc.)
   */
  contentType: string;

  /**
   * Description of what this payload does
   */
  description: string;

  /**
   * Expected output/result
   */
  expectedOutput?: string;

  /**
   * Difficulty level to exploit
   */
  difficulty?: 'easy' | 'medium' | 'hard';

  /**
   * Success rate/reliability percentage
   */
  successRate?: number;
}

/**
 * Configuration for POC generation
 */
export interface PocGeneratorConfig {
  /**
   * Include code snippets in steps
   */
  includeCodeSnippets: boolean;

  /**
   * Include payload examples
   */
  includePayloads: boolean;

  /**
   * Include code flow visualization
   */
  includeCodeFlow: boolean;

  /**
   * Include remediation code
   */
  includeRemediation: boolean;

  /**
   * Verbosity level
   */
  verbosity: 'minimal' | 'normal' | 'detailed';

  /**
   * Format for output
   */
  format: 'json' | 'markdown' | 'html';

  /**
   * Whether to generate step diagrams
   */
  generateDiagrams: boolean;
}

/**
 * POC generation request
 */
export interface PocGenerationRequest {
  /**
   * The security finding to create POC for
   */
  finding: Finding;

  /**
   * Code snippet where vulnerability exists
   */
  vulnerableCode: string;

  /**
   * File path and line information
   */
  location: {
    file: string;
    line: number;
    column?: number;
  };

  /**
   * Configuration options
   */
  config: PocGeneratorConfig;
}

/**
 * POC generation result
 */
export interface PocGenerationResult {
  /**
   * Success status
   */
  success: boolean;

  /**
   * Generated POC
   */
  poc?: ProofOfConcept;

  /**
   * Error message if generation failed
   */
  error?: string;

  /**
   * Generation duration in milliseconds
   */
  duration: number;
}

/**
 * Report containing multiple POCs
 */
export interface PocReport {
  /**
   * Report metadata
   */
  metadata: {
    generatedAt: Date;
    totalPocs: number;
    vulnerabilityCount: number;
  };

  /**
   * List of generated POCs
   */
  pocs: ProofOfConcept[];

  /**
   * Summary statistics
   */
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}
