import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const removedSubpaths = [
  ['@mastra', 'core', 'agent-builder', 'ee'].join('/'),
  ['@mastra', 'editor', 'ee'].join('/'),
  ['@mastra', 'playground-ui', 'ee', 'signals'].join('/'),
];
const removedSubpathSet = new Set(removedSubpaths);
const sourceExtensions = new Set(['.cjs', '.js', '.jsx', '.mjs', '.ts', '.tsx']);
const skippedDirectories = new Set(['.git', '.next', '.turbo', 'coverage', 'dist', 'node_modules']);

function isExcluded(relativePath: string): boolean {
  const normalized = relativePath.split(path.sep).join('/');
  return normalized === '.changeset' || normalized.startsWith('.changeset/');
}

function findSourceFiles(directory: string, rootDirectory = repoRoot): string[] {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const filePath = path.join(directory, entry.name);
    const relativePath = path.relative(rootDirectory, filePath);

    if (entry.isDirectory()) {
      if (skippedDirectories.has(entry.name) || isExcluded(relativePath)) return [];
      return findSourceFiles(filePath, rootDirectory);
    }

    if (!sourceExtensions.has(path.extname(entry.name)) || isExcluded(relativePath)) return [];
    return [filePath];
  });
}

function scriptKind(filePath: string): ts.ScriptKind {
  switch (path.extname(filePath)) {
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.jsx':
      return ts.ScriptKind.JSX;
    case '.js':
    case '.mjs':
    case '.cjs':
      return ts.ScriptKind.JS;
    default:
      return ts.ScriptKind.TS;
  }
}

type Offender = {
  file: string;
  line: number;
  importKind: 'import' | 'dynamic import' | 'require';
  specifier: string;
};

function findActiveImports(filePath: string): Offender[] {
  return findActiveImportsInSource(filePath, fs.readFileSync(filePath, 'utf8'));
}

function findActiveImportsInSource(filePath: string, sourceText: string): Offender[] {
  if (!removedSubpaths.some(specifier => sourceText.includes(specifier))) return [];

  const source = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true, scriptKind(filePath));
  const offenders: Offender[] = [];

  const record = (node: ts.Node, moduleSpecifier: ts.StringLiteral, importKind: Offender['importKind']) => {
    if (!removedSubpathSet.has(moduleSpecifier.text)) return;
    offenders.push({
      file: path.relative(repoRoot, filePath).split(path.sep).join('/'),
      line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
      importKind,
      specifier: moduleSpecifier.text,
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      record(node, node.moduleSpecifier, 'import');
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)
    ) {
      record(node, node.moduleReference.expression, 'import');
    } else if (ts.isCallExpression(node) && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
      const [argument] = node.arguments;
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        record(node, argument, 'dynamic import');
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        record(node, argument, 'require');
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(source);
  return offenders;
}

const importFixtures = removedSubpaths.map(specifier => ({
  specifier,
  source: [`import * as removed from '${specifier}';`, `void import('${specifier}');`].join('\n'),
}));

describe('removed package subpaths', () => {
  it('have no active imports in source files', () => {
    const offenders = findSourceFiles(repoRoot).flatMap(findActiveImports);

    expect(
      offenders,
      `Found active imports of removed package subpaths:\n${offenders
        .map(offender => `  ${offender.file}:${offender.line} (${offender.importKind}) ${offender.specifier}`)
        .join('\n')}`,
    ).toEqual([]);
  });

  it.each(importFixtures)('detects static and dynamic imports for $specifier', ({ specifier, source }) => {
    const offenders = findActiveImportsInSource(path.join(repoRoot, 'removed-ee-import-fixture.ts'), source);

    expect(
      offenders.map(({ importKind, specifier: foundSpecifier }) => ({ importKind, specifier: foundSpecifier })),
    ).toEqual([
      { importKind: 'import', specifier },
      { importKind: 'dynamic import', specifier },
    ]);
  });
  it('detects imports in active changelog sources while excluding changeset markdown', () => {
    const { specifier, source } = importFixtures[0];
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'removed-ee-imports-'));
    const changelogPath = path.join(fixtureRoot, 'src', 'changelog.ts');
    const changesetPath = path.join(fixtureRoot, '.changeset', 'fixture.md');

    try {
      fs.mkdirSync(path.dirname(changelogPath), { recursive: true });
      fs.mkdirSync(path.dirname(changesetPath), { recursive: true });
      fs.writeFileSync(changelogPath, source);
      fs.writeFileSync(changesetPath, source);

      const sourceFiles = findSourceFiles(fixtureRoot, fixtureRoot);
      expect(sourceFiles).toEqual([changelogPath]);
      expect(
        sourceFiles.flatMap(findActiveImports).map(({ importKind, specifier: foundSpecifier }) => ({
          importKind,
          specifier: foundSpecifier,
        })),
      ).toEqual([
        { importKind: 'import', specifier },
        { importKind: 'dynamic import', specifier },
      ]);
    } finally {
      fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });
});
