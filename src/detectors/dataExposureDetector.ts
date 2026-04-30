import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';

const POC_CONFIG = {
  includeCodeSnippets: true,
  includePayloads: true,
  includeCodeFlow: true,
  includeRemediation: true,
  verbosity: 'detailed' as const,
  format: 'markdown' as const,
  generateDiagrams: true
};

export class DataExposureDetector {
  private findings: Finding[] = [];
  private generatedPocs: ProofOfConcept[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  detect(): DetectorResult {
    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isReturnStatement(node) || ts.isObjectLiteralExpression(node)) {
        this.checkUnfilteredResponses(node);
        this.checkSensitiveFieldExposure(node);
      }
    });
    return { findings: this.findings };
  }

  private checkUnfilteredResponses(node: ts.Node): void {
    const sourceText = node.getText(this.sourceFile);
    
    // Check for returning full objects without filtering
    if (/res\.send\(.*\)|\breturn\s+.*user|res\.json\(.*\)/.test(sourceText)) {
      if (/password|token|secret|key|apiKey|creditCard/.test(sourceText) && !/delete|filter|exclude|omit/.test(sourceText)) {
        const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        
        // const poc = this.pocGenerator.generate({...}); // POC generation disabled for now

        this.findings.push({
          file: this.filePath, line: lineNum, column: 0, severity: 'HIGH',
          category: 'DATA_EXPOSURE',
          title: 'Unfiltered sensitive data in API response',
          description: 'User objects contain passwords, tokens, or other sensitive fields that should be excluded',
          code: sourceText,
          recommendation: 'Filter sensitive fields before returning: const { password, ...safeUser } = user;'
        });
      }
    }
  }

  private checkSensitiveFieldExposure(node: ts.Node): void {
    const sourceText = node.getText(this.sourceFile);
    
    const sensitivePatterns = [
      { field: 'password', pattern: /\.password\s*[,}]/ },
      { field: 'apiKey', pattern: /\.apiKey\s*[,}]/ },
      { field: 'secret', pattern: /\.secret\s*[,}]/ },
      { field: 'creditCard', pattern: /\.creditCard\s*[,}]/ },
      { field: 'ssn', pattern: /\.ssn\s*[,}]/ },
      { field: 'token', pattern: /\.token\s*[,}]/ }
    ];

    for (const { field, pattern } of sensitivePatterns) {
      if (pattern.test(sourceText) && /send|json|return|response/.test(sourceText)) {
        const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        
        this.findings.push({
          file: this.filePath, line: lineNum, column: 0, severity: 'HIGH',
          category: 'DATA_EXPOSURE',
          title: `Sensitive field "${field}" exposed in response`,
          description: `The "${field}" field should not be exposed in API responses`,
          code: sourceText,
          recommendation: `Exclude "${field}" field: const safeUser = { ...user }; delete safeUser.${field};`
        });
      }
    }
  }

  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }
}
