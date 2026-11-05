import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/', 'test/.bundle/'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['*.js', '*.mjs', 'tools/*.mjs', 'examples/*/*.mjs'],
        },
      },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      // Indexed access is checked (noUncheckedIndexedAccess); assertions mark proven indices.
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    files: ['src/**/*.ts'],
    ignores: ['src/cli/**'],
    rules: {
      // The core is portable and deterministic: no clock, randomness, or I/O.
      'no-restricted-globals': [
        'error',
        { name: 'fetch', message: 'The core performs no network access.' },
        { name: 'XMLHttpRequest', message: 'The core performs no network access.' },
        { name: 'WebSocket', message: 'The core performs no network access.' },
        { name: 'process', message: 'The core does not read the environment.' },
        { name: 'Buffer', message: 'The core is browser-compatible.' },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[object.name='Date'][property.name='now']",
          message: 'Use the caller-supplied evaluationTime.',
        },
        {
          selector: "NewExpression[callee.name='Date'][arguments.length=0]",
          message: 'Use the caller-supplied evaluationTime.',
        },
        {
          selector: "MemberExpression[object.name='Math'][property.name='random']",
          message: 'The core is deterministic.',
        },
        {
          selector: 'ImportDeclaration[source.value=/^node:/]',
          message: 'The core must not import Node.js modules.',
        },
      ],
    },
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { globals: globals.node },
  },
);
