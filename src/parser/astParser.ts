import * as ts from 'typescript';
import * as fs from 'fs';
import { Logger } from '../utils/logger';

export class ASTParser {
  private sourceFile: ts.SourceFile | null = null;
  private program: ts.Program | null = null;
  private typeChecker: ts.TypeChecker | null = null;
  private lastError: string | null = null;

  constructor(private filePath: string) {}

  parse(): ts.SourceFile | null {
    try {
      this.lastError = null;
      const content = fs.readFileSync(this.filePath, 'utf-8');
      this.sourceFile = ts.createSourceFile(
        this.filePath,
        content,
        ts.ScriptTarget.Latest,
        true
      );
      const diagnostics =
        (
          this.sourceFile as ts.SourceFile & {
            parseDiagnostics?: readonly ts.DiagnosticWithLocation[];
          }
        ).parseDiagnostics ?? [];
      if (diagnostics.length > 0) {
        this.lastError = ts.flattenDiagnosticMessageText(
          diagnostics[0].messageText,
          '\n'
        );
        this.sourceFile = null;
        return null;
      }
      return this.sourceFile;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.lastError = errorMessage;
      Logger.error(`Error parsing file ${this.filePath}`, { error: errorMessage });
      return null;
    }
  }

  getSourceFile(): ts.SourceFile | null {
    return this.sourceFile || this.parse();
  }

  setProgram(program: ts.Program): void {
    this.program = program;
    this.typeChecker = program.getTypeChecker();
  }

  getTypeChecker(): ts.TypeChecker | null {
    return this.typeChecker;
  }

  getProgram(): ts.Program | null {
    return this.program;
  }

  getLastError(): string | null {
    return this.lastError;
  }

  getLineAndColumn(position: number): { line: number; column: number } {
    if (!this.sourceFile) return { line: 1, column: 1 };
    
    const lineBreaks = this.sourceFile.getLineStarts();
    let line = 1;
    let col = 1;

    for (let i = 0; i < lineBreaks.length; i++) {
      if (lineBreaks[i] > position) {
        line = i;
        col = position - lineBreaks[i - 1] + 1;
        break;
      }
    }

    if (position >= lineBreaks[lineBreaks.length - 1]) {
      line = lineBreaks.length;
      col = position - lineBreaks[lineBreaks.length - 1] + 1;
    }

    return { line, column: col };
  }

  getCodeSnippet(position: number, length: number = 50): string {
    if (!this.sourceFile) return '';
    const text = this.sourceFile.text;
    const start = Math.max(0, position - 10);
    const end = Math.min(text.length, position + length + 10);
    return text.substring(start, end).trim();
  }
}

export class ASTParserBuilder {
  private files: string[] = [];
  private compilerOptions: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    strict: true,
  };

  addFile(filePath: string): this {
    this.files.push(filePath);
    return this;
  }

  addFiles(filePaths: string[]): this {
    this.files.push(...filePaths);
    return this;
  }

  setCompilerOptions(options: ts.CompilerOptions): this {
    this.compilerOptions = { ...this.compilerOptions, ...options };
    return this;
  }

  build(): Map<string, ASTParser> {
    const parsers = new Map<string, ASTParser>();

    for (const file of this.files) {
      const parser = new ASTParser(file);
      parser.parse();
      parsers.set(file, parser);
    }

    const program = ts.createProgram(this.files, this.compilerOptions);
    for (const [, parser] of parsers) {
      parser.setProgram(program);
    }

    return parsers;
  }
}
