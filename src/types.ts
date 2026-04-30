import { ProofOfConcept } from './poc/types';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type IssueCategory = 
  | 'AUTHENTICATION' 
  | 'VALIDATION' 
  | 'LOGGING' 
  | 'MASS_ASSIGNMENT' 
  | 'ACCESS_CONTROL' 
  | 'RATE_LIMITING' 
  | 'BUSINESS_LOGIC' 
  | 'API_KEY_EXPOSURE' 
  | 'CRYPTO_WEAKNESS' 
  | 'DATA_EXPOSURE'
  | 'CACHE_POISONING'
  | 'MESSAGE_QUEUE'
  | 'EVENT_STREAM';

export type RuntimeIssueType =
  | 'INVALID_TARGET'
  | 'PARSE_FAILURE'
  | 'DETECTOR_FAILURE'
  | 'POC_EXPORT_FAILURE'
  | 'REPORT_WRITE_FAILURE'
  | 'FATAL_ANALYSIS_FAILURE';

export type RuntimeIssueSeverity = 'ERROR' | 'WARNING';

export interface RuntimeIssue {
  type: RuntimeIssueType;
  severity: RuntimeIssueSeverity;
  message: string;
  file?: string;
  detector?: string;
  outputPath?: string;
}

export interface Finding {
  category: IssueCategory;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  code: string;
  recommendation: string;
  poc?: ProofOfConcept;
  injectionType?: string;
}

export interface AnalysisReport {
  timestamp: string;
  filesAnalyzed: number;
  totalFindings: number;
  findingsByCategory: Record<IssueCategory, number>;
  findingsBySeverity: Record<Severity, number>;
  findings: Finding[];
  runtimeIssues: RuntimeIssue[];
  runtimeIssuesByType: Record<RuntimeIssueType, number>;
  hasRuntimeErrors: boolean;
}

export interface DetectorResult {
  findings: Finding[];
}

export interface FileInfo {
  path: string;
  content: string;
  ast?: unknown;
}
