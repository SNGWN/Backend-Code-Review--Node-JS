import { ExploitationStep } from './types';

/**
 * Enhanced Code Flow Analyzer
 * 
 * Advanced visualization of execution paths with:
 * - Variable tracking through execution
 * - Function call chains
 * - Data transformation visualization
 * - Timing and concurrency analysis
 */
export class EnhancedCodeFlowAnalyzer {
  /**
   * Generate execution timeline showing variable transformations
   */
  static generateExecutionTimeline(steps: ExploitationStep[]): string {
    const timeline: string[] = ['# Execution Timeline\n'];
    
    steps.forEach((step, index) => {
      const time = `T+${(index * 100)}ms`;
      timeline.push(`\n**[${time}] Step ${step.stepNumber}: ${step.description}**`);
      timeline.push(`- Actor: ${step.actor}`);
      if (step.payload) {
        timeline.push(`- Payload: \`${JSON.stringify(step.payload).substring(0, 60)}...\``);
      }
      if (step.expectedResult) {
        timeline.push(`- Expected: ${step.expectedResult.substring(0, 80)}...`);
      }
    });

    return timeline.join('\n');
  }

  /**
   * Visualize data flow from input through vulnerability to output
   */
  static generateDataFlowDiagram(
    inputSource: string,
    vulnerableFunction: string,
    outputPoint: string
  ): string {
    return `
# Data Flow Diagram

\`\`\`
┌─────────────────────┐
│  INPUT SOURCE       │
│  ${inputSource.substring(0, 17)}  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  DATA PROCESSING    │
│  (Unsanitized)      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  VULNERABLE CODE    │
│  ${vulnerableFunction.substring(0, 17)}  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  EXPLOITATION       │
│  (Malicious exec)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  OUTPUT POINT       │
│  ${outputPoint.substring(0, 17)}  │
└─────────────────────┘
\`\`\`

**Critical Path Analysis**:
1. User-controlled input flows directly to vulnerable function
2. No sanitization or validation applied
3. Vulnerability exploited at function boundary
4. Impact visible in system response`;
  }

  /**
   * Generate sequence diagram for request/response exploitation
   */
  static generateSequenceDiagram(
    client: string,
    server: string,
    steps: ExploitationStep[]
  ): string {
    const diagram: string[] = ['\n# Request-Response Sequence\n'];
    
    diagram.push('\`\`\`');
    diagram.push(`${client.padEnd(20)} ${server.padEnd(20)}`);
    diagram.push(`   │                    │`);

    steps.forEach((step) => {
      if (step.actor === 'attacker' || step.actor === 'frontend') {
        diagram.push(`   │────────────────────▶ ${step.description.substring(0, 20)}`);
      } else if (step.actor === 'backend' || step.actor === 'database') {
        diagram.push(`   │ ◀────────────────────  ${step.description.substring(0, 20)}`);
      }
    });

    diagram.push(`   │                    │`);
    diagram.push('\`\`\`');

    return diagram.join('\n');
  }

  /**
   * Analyze and visualize component interaction in microservices
   */
  static generateMicroserviceInteractionMap(components: string[]): string {
    const map: string[] = ['# Microservice Interaction Map\n'];
    
    map.push('\`\`\`');
    
    // Create a simple interaction matrix
    components.forEach((comp, i) => {
      map.push(`${i + 1}. ${comp}`);
    });

    map.push('\nAttack Vector Paths:');
    
    for (let i = 0; i < components.length; i++) {
      for (let j = 0; j < components.length; j++) {
        if (i !== j) {
          map.push(`${i + 1} ──▶ ${j + 1}`);
        }
      }
    }

    map.push('\`\`\`');
    
    return map.join('\n');
  }

  /**
   * Generate a detailed exploit chain visualization
   */
  static generateExploitChain(
    initialVuln: string,
    chainedVulns: string[],
    finalImpact: string
  ): string {
    const chain: string[] = ['\n# Exploit Chain\n'];
    
    chain.push('\`\`\`');
    chain.push(`[1] ${initialVuln}`);
    chain.push(`    │`);
    
    chainedVulns.forEach((vuln, index) => {
      chain.push(`    ├─ [${index + 2}] ${vuln}`);
    });
    
    chain.push(`    │`);
    chain.push(`    ▼`);
    chain.push(`[${chainedVulns.length + 2}] ${finalImpact}`);
    chain.push('\`\`\`');

    return chain.join('\n');
  }

  /**
   * Identify and visualize exploit dependencies
   */
  static analyzeExploitDependencies(steps: ExploitationStep[]): string {
    const deps: string[] = ['\n# Exploit Dependency Graph\n'];

    deps.push('**Prerequisite Analysis**:\n');

    steps.forEach((step, index) => {
      if (index === 0) {
        deps.push(`- Step ${step.stepNumber}: Initial payload (no prerequisites)`);
      } else {
        deps.push(`- Step ${step.stepNumber}: Requires step ${step.stepNumber - 1} completion`);
      }
    });

    deps.push('\n**Critical Junctures**:');
    deps.push('- Authentication bypass required before accessing protected resources');
    deps.push('- Input validation bypass enables injection attacks');
    deps.push('- Access control flaws enable privilege escalation');

    return deps.join('\n');
  }

  /**
   * Generate timing analysis for race condition exploits
   */
  static generateTimingAnalysis(operationName: string, timeWindow: number): string {
    return `
# Timing Analysis

**Operation**: ${operationName}  
**Critical Window**: ${timeWindow}ms

## Race Condition Pattern

\`\`\`
Thread 1: [Check] ──────────────────── [Use] ─────
          │                            │
          └── Time Gap (${timeWindow}ms) ──┘
          
Thread 2: ──────────────── [Modify] ─────────────
\`\`\`

**Exploitation**: Attacker exploits timing gap between check and use operations.

**Impact**: Unauthorized state modification, logic bypass`;
  }

  /**
   * Detect and visualize multi-stage exploitation
   */
  static detectExploitStages(steps: ExploitationStep[]): string[] {
    const stages: string[] = [];
    let currentStage = 'Reconnaissance';

    steps.forEach((step) => {
      if (step.stepNumber <= 2) {
        currentStage = 'Reconnaissance';
      } else if (step.stepNumber <= 4) {
        currentStage = 'Exploitation Setup';
      } else if (step.stepNumber <= 6) {
        currentStage = 'Active Exploitation';
      } else {
        currentStage = 'Post-Exploitation';
      }

      if (!stages.includes(currentStage)) {
        stages.push(currentStage);
      }
    });

    return stages;
  }
}
