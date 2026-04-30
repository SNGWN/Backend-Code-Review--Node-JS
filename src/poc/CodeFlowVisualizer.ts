import { CodeFlow, FlowComponent, FlowConnection } from './types';

/**
 * Code Flow Visualizer
 *
 * Creates visual representations of how vulnerable code is executed,
 * showing the complete path from user input to exploitation.
 * Provides both text-based diagrams and structured flow data.
 */
export class CodeFlowVisualizer {
  /**
   * Generate a simple request→vulnerable→response flow
   */
  static generateSimpleFlow(
    vulnerableFileName: string,
    vulnerableLineNumber: number,
    vulnerableOperation: string
  ): CodeFlow {
    const components: FlowComponent[] = [
      {
        id: 'input',
        name: 'User Input',
        type: 'input',
        description: 'Attacker-supplied data in request',
      },
      {
        id: 'recv',
        name: 'Request Handler',
        type: 'processing',
        location: `${vulnerableFileName}:${vulnerableLineNumber}`,
        description: 'Parse incoming request',
      },
      {
        id: 'vuln',
        name: vulnerableOperation,
        type: 'vulnerable',
        location: `${vulnerableFileName}:${vulnerableLineNumber}`,
        isVulnerable: true,
        description: 'Dangerous operation without validation',
      },
      {
        id: 'output',
        name: 'Response',
        type: 'output',
        description: 'Send response back to attacker',
      },
    ];

    const connections: FlowConnection[] = [
      {
        from: 'input',
        to: 'recv',
        label: 'HTTP Request',
        isVulnerable: true,
      },
      {
        from: 'recv',
        to: 'vuln',
        label: 'Unsanitized data',
        isVulnerable: true,
      },
      {
        from: 'vuln',
        to: 'output',
        label: 'Response data',
      },
    ];

    const diagram = CodeFlowVisualizer.generateDiagram(components, connections);

    return {
      diagram,
      components,
      connections,
    };
  }

  /**
   * Generate a multi-step flow with detailed components
   */
  static generateComplexFlow(
    steps: Array<{
      id: string;
      name: string;
      location?: string;
      isVulnerable?: boolean;
      description: string;
    }>
  ): CodeFlow {
    const components: FlowComponent[] = steps.map((step) => ({
      id: step.id,
      name: step.name,
      type: step.isVulnerable ? 'vulnerable' : 'processing',
      location: step.location,
      isVulnerable: step.isVulnerable,
      description: step.description,
    }));

    // Create connections between sequential steps
    const connections: FlowConnection[] = [];
    for (let i = 0; i < components.length - 1; i++) {
      connections.push({
        from: components[i].id,
        to: components[i + 1].id,
        isVulnerable: components[i].isVulnerable || components[i + 1].isVulnerable,
      });
    }

    const diagram = CodeFlowVisualizer.generateDiagram(components, connections);

    return {
      diagram,
      components,
      connections,
    };
  }

  /**
   * Generate ASCII diagram from components and connections
   */
  static generateDiagram(components: FlowComponent[], connections: FlowConnection[]): string {
    const lines: string[] = [];

    lines.push('╔════════════════════════════════════════════════════════════╗');
    lines.push('║                  Code Execution Flow                       ║');
    lines.push('╚════════════════════════════════════════════════════════════╝');
    lines.push('');

    // Find the chain starting from input/first component
    const chain = CodeFlowVisualizer.buildChain(components, connections);

    chain.forEach((componentId, index) => {
      const component = components.find((c) => c.id === componentId);
      if (!component) return;

      const marker = component.isVulnerable ? '⚠️  ' : '→  ';
      const bracket = `[Step ${index + 1}]`;

      lines.push(`${marker}${bracket.padEnd(10)} ${component.name}`);
      if (component.location) {
        lines.push(`           ${component.location}`);
      }
      lines.push(`           ${component.description}`);

      // Add connection info
      if (index < chain.length - 1) {
        const conn = connections.find((c) => c.from === componentId && c.to === chain[index + 1]);
        if (conn) {
          const arrow = conn.isVulnerable ? '    ⬇️  [VULNERABLE]' : '    ⬇️';
          if (conn.label) {
            lines.push(`${arrow} Data: ${conn.label}`);
          } else {
            lines.push(arrow);
          }
        }
      }
      lines.push('');
    });

    return lines.join('\n');
  }

  /**
   * Generate a detailed flow with variable tracking
   */
  static generateFlowWithVariableTracking(
    vulnerableCode: string,
    startFile: string,
    startLine: number,
    inputVariable: string,
    vulnerableOperation: string
  ): CodeFlow {
    const lines = vulnerableCode.split('\n');

    // Find where input variable is used
    const usageLine = lines.findIndex((line) => line.includes(vulnerableOperation));

    const components: FlowComponent[] = [
      {
        id: 'user_input',
        name: 'User Input',
        type: 'input',
        description: `Attacker controls: ${inputVariable}`,
      },
      {
        id: 'parse',
        name: 'Parse Request',
        type: 'processing',
        location: `${startFile}:${startLine}`,
        description: `Extract ${inputVariable} from request`,
      },
      {
        id: 'assign',
        name: 'Variable Assignment',
        type: 'processing',
        location: `${startFile}:${startLine + 1}`,
        description: `Assign to local variable without validation`,
      },
      {
        id: 'use',
        name: 'Dangerous Operation',
        type: 'vulnerable',
        location: `${startFile}:${startLine + (usageLine > 0 ? usageLine : 2)}`,
        isVulnerable: true,
        description: vulnerableOperation,
      },
    ];

    const connections: FlowConnection[] = [
      {
        from: 'user_input',
        to: 'parse',
        data: inputVariable,
        isVulnerable: true,
      },
      {
        from: 'parse',
        to: 'assign',
        data: inputVariable,
        isVulnerable: true,
      },
      {
        from: 'assign',
        to: 'use',
        data: inputVariable,
        isVulnerable: true,
      },
    ];

    const diagram = CodeFlowVisualizer.generateDiagram(components, connections);

    return {
      diagram,
      components,
      connections,
    };
  }

  /**
   * Generate mermaid diagram (for markdown rendering)
   */
  static generateMermaidDiagram(components: FlowComponent[], connections: FlowConnection[]): string {
    const lines: string[] = ['graph TD'];

    // Add components
    components.forEach((comp) => {
      const icon = comp.isVulnerable ? '⚠️' : '';
      const label = `${comp.name}<br/>${icon}${comp.location || ''}`;
      lines.push(`  ${comp.id}["${label}"]`);
    });

    lines.push('');

    // Add connections
    connections.forEach((conn) => {
      const style = conn.isVulnerable ? '|VULNERABLE|' : '';
      lines.push(`  ${conn.from} -->|${conn.label || style}| ${conn.to}`);
    });

    lines.push('');
    lines.push('  classDef vulnerable fill:#ff6b6b,stroke:#c92a2a,color:#fff;');
    lines.push('  classDef input fill:#4dabf7,stroke:#1971c2,color:#fff;');
    lines.push('  classDef output fill:#51cf66,stroke:#2f9e44,color:#fff;');

    // Add vulnerable class
    components.forEach((comp) => {
      if (comp.isVulnerable) {
        lines.push(`  class ${comp.id} vulnerable;`);
      } else if (comp.type === 'input') {
        lines.push(`  class ${comp.id} input;`);
      } else if (comp.type === 'output') {
        lines.push(`  class ${comp.id} output;`);
      }
    });

    return lines.join('\n');
  }

  /**
   * Build the linear chain of components from connections
   */
  private static buildChain(components: FlowComponent[], connections: FlowConnection[]): string[] {
    // Find the first component (no incoming connections)
    const allTargets = new Set(connections.map((c) => c.to));
    let current = components.find((c) => !allTargets.has(c.id))?.id;

    if (!current) {
      // Fallback: just use components in order
      return components.map((c) => c.id);
    }

    const chain: string[] = [current];

    while (true) {
      const next = connections.find((c) => c.from === current)?.to;
      if (!next || chain.includes(next)) break;
      chain.push(next);
      current = next;
    }

    return chain;
  }

  /**
   * Generate ASCII table showing variable flow
   */
  static generateVariableFlowTable(
    flows: Array<{
      variable: string;
      step: number;
      value: string;
      source: string;
      validated: boolean;
    }>
  ): string {
    const lines: string[] = [];

    lines.push('Variable Flow Analysis:');
    lines.push('');
    lines.push('┌─────────────┬────┬──────────┬────────────┬───────────┐');
    lines.push('│ Variable    │ #  │ Value    │ Source     │ Validated │');
    lines.push('├─────────────┼────┼──────────┼────────────┼───────────┤');

    flows.forEach((flow) => {
      const validated = flow.validated ? '✓' : '✗ DANGER';
      lines.push(
        `│ ${flow.variable.padEnd(11)} │ ${String(flow.step).padStart(2)} │ ${flow.value.substring(0, 8).padEnd(8)} │ ${flow.source.padEnd(10)} │ ${validated.padEnd(9)} │`
      );
    });

    lines.push('└─────────────┴────┴──────────┴────────────┴───────────┘');

    return lines.join('\n');
  }

  /**
   * Generate step-by-step execution visualization
   */
  static generateExecutionSteps(
    steps: Array<{
      number: number;
      description: string;
      code?: string;
      actor: string;
      result?: string;
    }>
  ): string {
    const lines: string[] = [];

    lines.push('Exploitation Steps:');
    lines.push('');

    steps.forEach((step) => {
      lines.push(`${step.number}. ${step.description}`);
      lines.push(`   Actor: ${step.actor}`);

      if (step.code) {
        lines.push(`   Code: ${step.code.substring(0, 50)}${step.code.length > 50 ? '...' : ''}`);
      }

      if (step.result) {
        lines.push(`   Result: ${step.result}`);
      }

      lines.push('');
    });

    return lines.join('\n');
  }
}
