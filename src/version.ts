declare const __PACKAGE_VERSION__: string;

export const PACKAGE_NAME = '@su-engineering/eudi-disclosure-policy';
/** Injected from package.json at build time. */
export const VERSION: string = __PACKAGE_VERSION__;
/**
 * Version of the rule catalog and verdict mapping. Bumped whenever a rule's
 * trigger, default verdict, or category changes, independently of releases
 * that only touch documentation or tooling.
 */
export const RULES_VERSION = '1.0.0';
