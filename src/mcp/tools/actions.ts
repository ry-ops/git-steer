/**
 * Actions tools: actions_workflows, actions_trigger, actions_secrets
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';

export function getTools(): Tool[] {
  return [
    {
      name: 'actions_workflows',
      description: 'List workflows in a repository',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'actions_trigger',
      description: 'Manually trigger a workflow',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          workflow: { type: 'string', description: 'Workflow filename or ID' },
          ref: { type: 'string', description: 'Branch or tag', default: 'main' },
          inputs: {
            type: 'object',
            description: 'Workflow inputs',
          },
        },
        required: ['owner', 'repo', 'workflow'],
      },
    },
    {
      name: 'actions_secrets',
      description: 'Manage Actions secrets',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          action: {
            type: 'string',
            enum: ['list', 'set', 'delete'],
          },
          name: { type: 'string' },
          value: { type: 'string', description: 'Secret value (for set)' },
        },
        required: ['owner', 'repo', 'action'],
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'actions_workflows': return handleActionsWorkflows(args, deps);
    case 'actions_trigger': return handleActionsTrigger(args, deps);
    case 'actions_secrets': return handleActionsSecrets(args, deps);
    default: return null;
  }
}

async function handleActionsWorkflows(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const workflows = await deps.github.listWorkflows(args.owner, args.repo);
  return workflows;
}

async function handleActionsTrigger(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  await deps.github.triggerWorkflow(
    args.owner,
    args.repo,
    args.workflow,
    args.ref || 'main',
    args.inputs
  );
  return {
    triggered: true,
    workflow: args.workflow,
    ref: args.ref || 'main',
  };
}

async function handleActionsSecrets(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  switch (args.action) {
    case 'list': {
      const secrets = await deps.github.listSecrets(args.owner, args.repo);
      return secrets;
    }
    case 'set': {
      if (!args.name || !args.value) {
        throw new Error('name and value are required for setting a secret');
      }
      await deps.github.setSecret(args.owner, args.repo, args.name, args.value);
      return { set: true, name: args.name };
    }
    case 'delete': {
      if (!args.name) {
        throw new Error('name is required for deleting a secret');
      }
      await deps.github.deleteSecret(args.owner, args.repo, args.name);
      return { deleted: true, name: args.name };
    }
    default:
      throw new Error(`Unknown action: ${args.action}`);
  }
}
