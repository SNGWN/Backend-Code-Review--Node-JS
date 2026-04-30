import { ProofOfConcept, ExploitationStep, Payload } from '../types';
import { PocGenerator } from '../PocGenerator';
import { CodeFlowVisualizer } from '../CodeFlowVisualizer';
import { PocGenerationRequest, PocGenerationResult } from '../types';

/**
 * Hardcoded Secret/Credential POC Generator
 *
 * Generates detailed Proof-of-Concept documentation for hardcoded secrets,
 * credentials, API keys, and sensitive tokens found in source code.
 */
export class HardcodedSecretPocGenerator extends PocGenerator {
  /**
   * Generate POC for hardcoded secret
   */
  generate(request: PocGenerationRequest): PocGenerationResult {
    const startTime = Date.now();

    try {
      const secretType = this.identifySecretType(request.vulnerableCode);
      const poc = this.createBasePoc(
        `hardcoded-secret-${request.location.line}`,
        `Hardcoded ${secretType} in Source Code`,
        'Hardcoded Secret/Credential',
        'CRITICAL',
        request
      );

      // Build exploitation steps
      poc.steps = this.buildExploitationSteps(request, secretType);

      // Build code flow
      poc.codeFlow = CodeFlowVisualizer.generateSimpleFlow(
        request.location.file,
        request.location.line,
        'Read hardcoded secret from code'
      );

      // Set description
      poc.description = this.buildDescription(secretType, request.vulnerableCode);

      // Set root cause
      poc.rootCause = `The ${secretType} is hardcoded directly in the source code at ${request.location.file}:${request.location.line}. 
Anyone with access to the source code repository can extract and misuse this credential.`;

      // Build impacts
      poc.businessImpact = this.getBussinessImpact(secretType);
      poc.technicalImpact = this.getTechnicalImpact(secretType);

      // Build payloads
      poc.payloads = this.buildPayloads(secretType, request.vulnerableCode);

      // Remediation
      poc.remediationDescription = `Move the ${secretType} to an environment variable or secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.). Never commit secrets to version control.`;
      poc.remediationCode = this.getRemediationCode(secretType);

      // Add preconditions
      poc.preconditions = [
        'Attacker has access to source code repository or compiled application',
        'Application uses the hardcoded credential at runtime',
        `${secretType} grants access to a sensitive resource`,
      ];

      // OWASP reference
      poc.owaspCategory = 'A02:2021 – Cryptographic Failures';
      poc.cvssScore = 9.8;

      return {
        success: true,
        poc,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: `Failed to generate hardcoded secret POC: ${errorMessage}`,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Identify the type of secret
   */
  private identifySecretType(code: string): string {
    const keywords = [
      { pattern: /password|pwd|passwd/i, type: 'Password' },
      { pattern: /api[_-]?key|apikey|api_key/i, type: 'API Key' },
      { pattern: /secret|SECRET/i, type: 'Secret Key' },
      { pattern: /token|jwt|access_token/i, type: 'Access Token' },
      { pattern: /private[_-]?key|privatekey|private_key/i, type: 'Private Key' },
      { pattern: /db[_-]?password|database[_-]?password/i, type: 'Database Password' },
      { pattern: /oauth|bearer/i, type: 'OAuth Token' },
    ];

    for (const { pattern, type } of keywords) {
      if (pattern.test(code)) {
        return type;
      }
    }

    return 'Credential';
  }

  /**
   * Build exploitation steps
   */
  private buildExploitationSteps(request: PocGenerationRequest, secretType: string): ExploitationStep[] {
    const steps: ExploitationStep[] = [];

    // Step 1: Gain code access
    steps.push(
      this.createStep(
        1,
        'Gain Access to Source Code',
        'attacker',
        {
          description: 'Attacker obtains access to the source code repository through various means',
          actionType: 'reconnaissance',
          notes: `Access could be through: Git repository clone, compromised developer account, GitHub public repository, 
decompiled JAR/APK file, docker image analysis, or source code disclosure`,
        }
      )
    );

    // Step 2: Search for secrets
    steps.push(
      this.createStep(2, 'Search for Hardcoded Secrets', 'attacker', {
        actionType: 'analysis',
        codeSnippet: `# Search for secrets in repository\ngit log --all -p | grep -i "password\\|secret\\|api_key"\ngrep -r "password\\|secret\\|api_key" . --include="*.ts" --include="*.js"`,
        notes: 'Tools like TruffleHog, GitRob, and git-secrets can automate this search',
        expectedResult: 'Found ${secretType} in the source code',
      })
    );

    // Step 3: Extract credential
    steps.push(
      this.createStep(3, 'Extract and Copy Credential', 'attacker', {
        actionType: 'extraction',
        codeSnippet: request.vulnerableCode,
        filePath: request.location.file,
        lineNumber: request.location.line,
        expectedResult: `Credential value obtained: ${secretType}`,
        notes: 'The exact credential value is now in attacker\'s possession',
      })
    );

    // Step 4: Identify usage
    steps.push(
      this.createStep(4, 'Determine Credential Usage', 'attacker', {
        actionType: 'analysis',
        notes: `Search codebase for where this credential is used:
- API authentication headers
- Database connection strings
- Third-party service authentication
- Encryption keys`,
        expectedResult: 'Identified which services/APIs this credential grants access to',
      })
    );

    // Step 5: Use credential
    steps.push(
      this.createStep(5, 'Authenticate with Stolen Credential', 'attacker', {
        actionType: 'exploitation',
        payload: this.buildExploitPayload(secretType),
        expectedResult: 'Unauthorized access to protected resources granted',
        notes: 'Attacker now has full access as if they were the application',
      })
    );

    // Step 6: Exfiltrate data
    steps.push(
      this.createStep(6, 'Exfiltrate Sensitive Data', 'attacker', {
        actionType: 'data-theft',
        notes: `With credential in hand, attacker can:
- Query databases and extract all data
- Call APIs on behalf of the application
- Impersonate users or perform unauthorized actions
- Compromise connected systems`,
        expectedResult: 'Large-scale unauthorized data access',
      })
    );

    return steps;
  }

  /**
   * Build payloads for attacking
   */
  private buildPayloads(secretType: string, code: string): Payload[] {
    const payloads: Payload[] = [];

    // Extract the actual credential from the code (first quoted string)
    const secretMatch = code.match(/['"](.*?)['"]/) || code.match(/=\s*(['"][^'"]*['"])/);
    const secretValue = secretMatch ? secretMatch[1] : 'YOUR_SECRET_HERE';

    // Generic API Key payload
    payloads.push(
      this.createPayload(
        'API Request with Stolen Key',
        `curl -X GET https://api.example.com/v1/users \\
  -H "Authorization: Bearer ${secretValue}" \\
  -H "Content-Type: application/json"`,
        'bash',
        'Use the stolen credential to make authenticated API requests',
        {
          difficulty: 'easy',
          successRate: 100,
          expectedOutput: 'Full user database returned with sensitive data',
        }
      ) as Payload
    );

    // Database connection payload
    payloads.push(
      this.createPayload(
        'Database Connection Exploit',
        `const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'database.internal.com',
  user: 'admin',
  password: '${secretValue}',
  database: 'production_db'
});

connection.query('SELECT * FROM users', (err, results) => {
  console.log(results); // All user data exposed
});`,
        'javascript',
        'Connect to the database using the hardcoded credentials',
        {
          difficulty: 'easy',
          successRate: 100,
          expectedOutput: 'Complete database contents accessible',
        }
      ) as Payload
    );

    // OAuth/API Key enumeration
    payloads.push(
      this.createPayload(
        'API Key Reuse/Enumeration',
        `// Use key across multiple services
const apiKey = '${secretValue}';

// Twilio API
const twilioClient = require('twilio')(apiKey);

// SendGrid API
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(apiKey);

// AWS API (if same key pattern)
const AWS = require('aws-sdk');
AWS.config.credentials = new AWS.Credentials(apiKey, apiKey);`,
        'javascript',
        'Reuse the same credential across multiple connected services',
        {
          difficulty: 'medium',
          successRate: 75,
          expectedOutput: 'Access to multiple cloud services and third-party APIs',
        }
      ) as Payload
    );

    return payloads;
  }

  /**
   * Build exploitation payload
   */
  private buildExploitPayload(secretType: string): string {
    if (secretType.includes('API')) {
      return `Authorization: Bearer YOUR_STOLEN_API_KEY\nX-API-Key: YOUR_STOLEN_API_KEY`;
    } else if (secretType.includes('Database')) {
      return `mysql -h database.server.com -u admin -p'YOUR_STOLEN_PASSWORD' production_db`;
    } else if (secretType.includes('Token')) {
      return `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`;
    } else {
      return `Authorization: Basic $(echo -n "user:YOUR_STOLEN_PASSWORD" | base64)`;
    }
  }

  /**
   * Build description
   */
  private buildDescription(secretType: string, code: string): string {
    return `A ${secretType} has been discovered hardcoded directly in the application source code. 
This credential is stored in plaintext and accessible to anyone who can view the source code or decompile the application. 

Hardcoded credentials are a critical security vulnerability because:
- They persist in version control history (even if deleted, git history retains them)
- They are exposed in compiled applications and docker images  
- They grant direct access to sensitive systems and data
- Rotation is difficult as the code would need to be redeployed
- Automated tools can easily find and extract them`;
  }

  /**
   * Get business impact
   */
  private getBussinessImpact(secretType: string): string {
    return `Exposure of a ${secretType} can lead to:

**Immediate Risks:**
- Unauthorized access to protected resources (APIs, databases, cloud services)
- Large-scale data breaches affecting all customer data
- Service disruption and account takeover
- Fraudulent transactions and financial loss
- Reputational damage and loss of customer trust

**Compliance & Legal:**
- GDPR, HIPAA, PCI-DSS violations with heavy fines
- Mandatory breach notifications
- Legal liability for customer data loss
- Loss of certifications and compliance status

**Long-term Damage:**
- Customer churn and business loss
- Diminished brand value
- Regulatory scrutiny and increased compliance costs`;
  }

  /**
   * Get technical impact
   */
  private getTechnicalImpact(secretType: string): string {
    return `Technical consequences of exposed ${secretType}:

**System Compromise:**
- Full unauthorized access to backend systems
- Ability to impersonate the application in API calls
- Direct database access with admin privileges
- Cloud infrastructure compromise
- Lateral movement to connected systems

**Data Exposure:**
- Complete database extraction (PII, payment data, medical records)
- Sensitive configuration exposure
- Customer account information theft
- Intellectual property and trade secrets access

**Infrastructure Impact:**
- Resource hijacking (compute, bandwidth, storage)
- Malware deployment and backdoor installation
- System misconfiguration and environmental exposure
- Audit trail manipulation and log deletion`;
  }

  /**
   * Get remediation code
   */
  private getRemediationCode(secretType: string): string {
    return `// ❌ VULNERABLE: Hardcoded credential
const API_KEY = 'sk-xxxxxxxxxxxxxxxxxxx';
const DB_PASSWORD = 'admin123password';
const SECRET = 'super-secret-key';

// ✅ FIXED: Use environment variables
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DATABASE_PASSWORD;
const SECRET = process.env.JWT_SECRET;

// ✅ BETTER: Validate secrets are provided
if (!API_KEY || !DB_PASSWORD || !SECRET) {
  throw new Error('Required environment variables not set');
}

// ✅ BEST: Use a secrets management service
import * as secretsManager from 'aws-sdk/clients/secretsmanager';

const getSecret = async (secretName: string) => {
  const client = new secretsManager({ region: 'us-east-1' });
  const result = await client.getSecretValue({ SecretId: secretName }).promise();
  return JSON.parse(result.SecretString || '{}');
};

const secrets = await getSecret('prod/database');`;
  }
}
