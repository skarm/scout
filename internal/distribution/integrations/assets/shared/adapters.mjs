// SPDX-License-Identifier: Apache-2.0
// Host SDK-independent factories. SDKs are supplied by Pi/OpenCode, not bundled mocks.
import { operatorConfig, runScan } from './runner.mjs';

export function registerPi(pi, Type, env = process.env) {
  const config = operatorConfig(env);
  pi.registerTool({
    name: 'scout_scan', label: 'Scout security review',
    description: 'Inspect an operator-approved skill/plugin alias. Static by default; explicit approval is required for source upload. Returns bounded evidence including block/partial results, not install permission.',
    promptSnippet: 'Review a named skill/plugin with the trusted scout CLI.',
    promptGuidelines: [
      'Use scout_scan before installing or updating third-party skills/plugins.',
      'scout_scan accepts only operator-defined aliases. Never invent a path, bypass permission prompts, or set semantic=true without source-upload approval.',
      'Keep scout_scan block/partial outcomes; read the reviewer skill and inspect source independently. A summary is not an approval.',
    ],
    parameters: Type.Object({ target: Type.String({ description: 'Operator-registered target alias, not a filesystem path.' }), semantic: Type.Optional(Type.Boolean({ description: 'Request configured source-upload review; false by default.' })) }, { additionalProperties: false }),
    async execute(_id, args, signal, _onUpdate, ctx) {
      if (!ctx?.hasUI || typeof ctx.ui?.confirm !== 'function') throw new Error('Interactive permission gate unavailable; no scan started');
      const authorize = async grant => {
        const approved = await ctx.ui.confirm('Scout permission', JSON.stringify({ capability: grant.permission, targets: grant.patterns, purpose: grant.description }));
        if (approved !== true) throw new Error('Review permission declined');
      };
      const result = await runScan(args, config, authorize, signal, env);
      return { content: [{ type: 'text', text: JSON.stringify(result) }], details: result };
    },
  });
}

export function openCodeDefinition(tool, env = process.env) {
  const config = operatorConfig(env);
  return tool({
    description: 'Review an operator-approved skill/plugin using scout. Static by default; keeps block/partial evidence. Source upload has a separate permission. No installation or arbitrary paths.',
    args: {
      target: tool.schema.string().describe('Operator-registered target alias.'),
      semantic: tool.schema.boolean().optional().describe('Explicit configured reviewer upload; false by default.'),
    },
    async execute(args, context) {
      if (typeof context?.ask !== 'function') throw new Error('Host permission gate unavailable; no scan started');
      const result = await runScan(args, config, async grant => {
        const outcome = await context.ask({ permission: grant.permission, patterns: grant.patterns, always: [], metadata: { purpose: grant.description, tool: 'scout_scan' } });
        if (outcome === false) throw new Error('Review permission declined');
      }, context.abort, env);
      return JSON.stringify(result);
    },
  });
}
