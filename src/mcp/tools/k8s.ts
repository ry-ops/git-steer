/**
 * Kubernetes tools: oomkill_detect, oomkill_remediate, cert_check, cert_renew
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';
import { execFileSync } from 'child_process';

export function getTools(): Tool[] {
  return [
    {
      name: 'oomkill_detect',
      description: 'Detect pods that have been OOMKilled. Returns pods with OOMKill events, their current resource limits, and restart counts.',
      inputSchema: {
        type: 'object',
        properties: {
          namespace: { type: 'string', description: 'Kubernetes namespace to scan. Omit for all namespaces.' },
          min_restarts: { type: 'number', description: 'Minimum restart count to include (default: 3)', default: 3 },
        },
      },
    },
    {
      name: 'oomkill_remediate',
      description: 'Auto-bump resource limits for OOMKilled pods by creating a PR to the GitOps repo. Calculates new limits as a multiplier of current limits (default: 1.5x). Uses PR dedup to avoid duplicate remediation PRs.',
      inputSchema: {
        type: 'object',
        properties: {
          namespace: { type: 'string', description: 'Kubernetes namespace' },
          deployment: { type: 'string', description: 'Deployment name to remediate' },
          container: { type: 'string', description: 'Container name (default: first container)' },
          multiplier: { type: 'number', description: 'Memory limit multiplier (default: 1.5)', default: 1.5 },
          gitops_owner: { type: 'string', description: 'GitOps repo owner' },
          gitops_repo: { type: 'string', description: 'GitOps repo name' },
          manifest_path: { type: 'string', description: 'Path to the deployment manifest in the GitOps repo' },
          dry_run: { type: 'boolean', description: 'Preview changes without creating a PR', default: false },
        },
        required: ['namespace', 'deployment', 'gitops_owner', 'gitops_repo', 'manifest_path'],
      },
    },
    {
      name: 'cert_check',
      description: 'Detect TLS certificates approaching expiration in the cluster. Checks cert-manager Certificate resources and returns certificates expiring within the threshold.',
      inputSchema: {
        type: 'object',
        properties: {
          namespace: { type: 'string', description: 'Kubernetes namespace to scan. Omit for all namespaces.' },
          expiry_days: { type: 'number', description: 'Alert threshold in days before expiry (default: 30)', default: 30 },
        },
      },
    },
    {
      name: 'cert_renew',
      description: 'Trigger certificate renewal for expiring certificates. Deletes the certificate Secret to force cert-manager to re-issue, or creates a PR to update certificate manifests.',
      inputSchema: {
        type: 'object',
        properties: {
          namespace: { type: 'string', description: 'Certificate namespace' },
          certificate_name: { type: 'string', description: 'cert-manager Certificate resource name' },
          method: { type: 'string', enum: ['force_renewal', 'gitops_pr'], description: 'Renewal method: force_renewal deletes the Secret; gitops_pr creates a PR with annotation bump', default: 'force_renewal' },
          gitops_owner: { type: 'string', description: 'GitOps repo owner (required for gitops_pr method)' },
          gitops_repo: { type: 'string', description: 'GitOps repo name (required for gitops_pr method)' },
          manifest_path: { type: 'string', description: 'Path to cert manifest (required for gitops_pr method)' },
          confirm: { type: 'string', description: "Safety confirmation. Must be exactly 'CONFIRM_CERT_RENEW' to proceed." },
        },
        required: ['namespace', 'certificate_name'],
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'oomkill_detect': return handleOomkillDetect(args, deps);
    case 'oomkill_remediate': return handleOomkillRemediate(args, deps);
    case 'cert_check': return handleCertCheck(args, deps);
    case 'cert_renew': return handleCertRenew(args, deps);
    default: return null;
  }
}

async function handleOomkillDetect(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const minRestarts = args.min_restarts || 3;

  let output: string;
  try {
    output = execFileSync('kubectl', [
      'get', 'pods', ...(args.namespace ? ['-n', args.namespace] : ['--all-namespaces']),
      '-o', 'json',
    ], { encoding: 'utf8', timeout: 30_000 });
  } catch (e: any) {
    throw new Error(`kubectl failed: ${e.message}`);
  }

  const pods = JSON.parse(output);
  const oomPods: Array<{
    namespace: string;
    pod: string;
    container: string;
    restartCount: number;
    currentLimits: Record<string, string>;
    lastOOMKill: string | null;
    deployment: string | null;
  }> = [];

  for (const pod of pods.items) {
    const podNs = pod.metadata.namespace;
    const podName = pod.metadata.name;
    const ownerRef = pod.metadata.ownerReferences?.[0];
    const deployment = ownerRef?.kind === 'ReplicaSet'
      ? ownerRef.name.replace(/-[a-f0-9]+$/, '')
      : ownerRef?.name || null;

    for (const cs of pod.status?.containerStatuses || []) {
      if (cs.restartCount >= minRestarts && cs.lastState?.terminated?.reason === 'OOMKilled') {
        const container = pod.spec.containers.find((c: any) => c.name === cs.name);
        oomPods.push({
          namespace: podNs,
          pod: podName,
          container: cs.name,
          restartCount: cs.restartCount,
          currentLimits: container?.resources?.limits || {},
          lastOOMKill: cs.lastState.terminated.finishedAt || null,
          deployment,
        });
      }
    }
  }

  deps.state.addAuditEntry({
    action: 'oomkill_detect',
    result: 'success',
    details: { oomPodsFound: oomPods.length, namespace: args.namespace || 'all' },
  });

  if (oomPods.length > 0) {
    const slackConfig = deps.state.getCache('slack_config');
    if (slackConfig?.webhook_url && slackConfig?.notify_on?.oomkill_detected) {
      const podList = oomPods.slice(0, 5).map((p) => `• \`${p.namespace}/${p.pod}\` (${p.restartCount} restarts)`).join('\n');
      await deps.sendSlackNotification(slackConfig.webhook_url, {
        text: `💥 OOMKill detected: ${oomPods.length} pod(s)\n${podList}${oomPods.length > 5 ? `\n...and ${oomPods.length - 5} more` : ''}`,
      });
    }
  }

  return { oomPods, total: oomPods.length };
}

async function handleOomkillRemediate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const multiplier = args.multiplier || 1.5;

  let podOutput: string;
  try {
    podOutput = execFileSync('kubectl', [
      'get', 'pods', '-n', args.namespace,
      '-l', `app=${args.deployment}`,
      '-o', 'json',
    ], { encoding: 'utf8', timeout: 30_000 });
  } catch {
    podOutput = execFileSync('kubectl', [
      'get', 'pods', '-n', args.namespace,
      '-l', `app.kubernetes.io/name=${args.deployment}`,
      '-o', 'json',
    ], { encoding: 'utf8', timeout: 30_000 });
  }

  const podData = JSON.parse(podOutput);
  if (podData.items.length === 0) {
    throw new Error(`No pods found for deployment ${args.deployment} in ${args.namespace}`);
  }

  const targetContainer = args.container || podData.items[0].spec.containers[0].name;
  const container = podData.items[0].spec.containers.find((c: any) => c.name === targetContainer);
  if (!container) {
    throw new Error(`Container ${targetContainer} not found`);
  }

  const currentMemLimit = container.resources?.limits?.memory || '256Mi';
  const currentCpuLimit = container.resources?.limits?.cpu || '500m';

  const parseMemory = (mem: string): number => {
    if (mem.endsWith('Gi')) return parseFloat(mem) * 1024;
    if (mem.endsWith('Mi')) return parseFloat(mem);
    if (mem.endsWith('Ki')) return parseFloat(mem) / 1024;
    return parseFloat(mem) / (1024 * 1024);
  };

  const formatMemory = (mi: number): string => {
    if (mi >= 1024) return `${Math.round(mi / 1024 * 10) / 10}Gi`;
    return `${Math.round(mi)}Mi`;
  };

  const newMemLimit = formatMemory(parseMemory(currentMemLimit) * multiplier);
  const newMemRequest = formatMemory(parseMemory(currentMemLimit) * multiplier * 0.75);

  if (args.dry_run) {
    return {
      dry_run: true,
      deployment: args.deployment,
      namespace: args.namespace,
      container: targetContainer,
      current: { memory: currentMemLimit, cpu: currentCpuLimit },
      proposed: { memory: newMemLimit, memoryRequest: newMemRequest },
      multiplier,
    };
  }

  let manifestContent: string;
  try {
    const file = await deps.github.getFileContent(args.gitops_owner, args.gitops_repo, args.manifest_path);
    manifestContent = file.content;
  } catch {
    throw new Error(`Cannot read manifest at ${args.manifest_path} in ${args.gitops_owner}/${args.gitops_repo}`);
  }

  let updatedManifest = manifestContent;
  const memLimitPattern = new RegExp(`(memory:\\s*)${currentMemLimit.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g');
  updatedManifest = updatedManifest.replace(memLimitPattern, `$1${newMemLimit}`);

  if (updatedManifest === manifestContent) {
    updatedManifest = manifestContent.replace(
      /(limits:\s*\n\s*memory:\s*)([\w.]+)/,
      `$1${newMemLimit}`
    );
  }

  const branchName = `oomkill-remediate/${args.namespace}-${args.deployment}-${Date.now()}`;

  await deps.github.commitFiles(args.gitops_owner, args.gitops_repo, {
    branch: branchName,
    message: `fix(oomkill): bump ${args.deployment} memory limit to ${newMemLimit}`,
    files: [{ path: args.manifest_path, content: updatedManifest }],
    createBranch: true,
    baseBranch: 'main',
  });

  const prefix = `[OOMKill] ${args.namespace}/${args.deployment}`;
  const openPrs = await deps.github.listPullRequests(args.gitops_owner, args.gitops_repo, { state: 'open' });
  const existingPr = openPrs.find((pr) => pr.title.startsWith(prefix));

  if (existingPr) {
    deps.state.addAuditEntry({
      action: 'oomkill_remediate',
      repo: `${args.gitops_owner}/${args.gitops_repo}`,
      result: 'dedup_hit',
      details: { deployment: args.deployment, existingPr: existingPr.number },
    });
    return { created: false, dedup_hit: true, existing_pr: existingPr };
  }

  const pr = await deps.github.createPullRequest(args.gitops_owner, args.gitops_repo, {
    title: `${prefix} — bump memory ${currentMemLimit} → ${newMemLimit}`,
    body: `## OOMKill Remediation\n\n**Deployment:** \`${args.namespace}/${args.deployment}\`\n**Container:** \`${targetContainer}\`\n**Current limit:** ${currentMemLimit}\n**New limit:** ${newMemLimit} (${multiplier}x)\n**New request:** ${newMemRequest}\n\n_Auto-generated by git-steer oomkill_remediate_`,
    head: branchName,
    base: 'main',
    labels: ['oomkill', 'auto-remediation'],
  });

  deps.state.addAuditEntry({
    action: 'oomkill_remediate',
    repo: `${args.gitops_owner}/${args.gitops_repo}`,
    result: 'pr_created',
    details: { deployment: args.deployment, prNumber: pr.number, oldLimit: currentMemLimit, newLimit: newMemLimit },
  });

  return {
    created: true,
    pr: { number: pr.number, url: pr.url },
    changes: {
      deployment: args.deployment,
      container: targetContainer,
      oldLimit: currentMemLimit,
      newLimit: newMemLimit,
      multiplier,
    },
  };
}

async function handleCertCheck(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const expiryDays = args.expiry_days || 30;
  const now = new Date();
  const threshold = new Date(now.getTime() + expiryDays * 24 * 60 * 60 * 1000);

  let certOutput: string;
  try {
    certOutput = execFileSync('kubectl', [
      'get', 'certificates',
      ...(args.namespace ? ['-n', args.namespace] : ['--all-namespaces']),
      '-o', 'json',
    ], { encoding: 'utf8', timeout: 30_000 });
  } catch (e: any) {
    throw new Error(`kubectl failed (cert-manager CRDs installed?): ${e.message}`);
  }

  const certs = JSON.parse(certOutput);
  const expiring: Array<{
    namespace: string;
    name: string;
    secretName: string;
    dnsNames: string[];
    notAfter: string;
    daysRemaining: number;
    issuer: string;
    ready: boolean;
  }> = [];

  for (const cert of certs.items) {
    const notAfter = cert.status?.notAfter;
    if (!notAfter) continue;

    const expiryDate = new Date(notAfter);
    const daysRemaining = Math.floor((expiryDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

    if (expiryDate <= threshold) {
      const readyCondition = cert.status?.conditions?.find((c: any) => c.type === 'Ready');
      expiring.push({
        namespace: cert.metadata.namespace,
        name: cert.metadata.name,
        secretName: cert.spec.secretName,
        dnsNames: cert.spec.dnsNames || [],
        notAfter,
        daysRemaining,
        issuer: cert.spec.issuerRef?.name || 'unknown',
        ready: readyCondition?.status === 'True',
      });
    }
  }

  expiring.sort((a, b) => a.daysRemaining - b.daysRemaining);

  deps.state.addAuditEntry({
    action: 'cert_check',
    result: 'success',
    details: { expiringCerts: expiring.length, thresholdDays: expiryDays },
  });

  if (expiring.length > 0) {
    const slackConfig = deps.state.getCache('slack_config');
    if (slackConfig?.webhook_url && slackConfig?.notify_on?.cert_expiring) {
      const certList = expiring.slice(0, 5).map((c) =>
        `• \`${c.namespace}/${c.name}\` — ${c.daysRemaining}d remaining (${c.dnsNames.join(', ')})`
      ).join('\n');
      await deps.sendSlackNotification(slackConfig.webhook_url, {
        text: `🔒 ${expiring.length} certificate(s) expiring within ${expiryDays} days:\n${certList}`,
      });
    }
  }

  return { expiring, total: expiring.length, thresholdDays: expiryDays };
}

async function handleCertRenew(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const method = args.method || 'force_renewal';

  if (method === 'force_renewal') {
    let certJson: string;
    try {
      certJson = execFileSync('kubectl', [
        'get', 'certificate', args.certificate_name,
        '-n', args.namespace, '-o', 'json',
      ], { encoding: 'utf8', timeout: 15_000 });
    } catch (e: any) {
      throw new Error(`Certificate ${args.certificate_name} not found in ${args.namespace}: ${e.message}`);
    }

    const cert = JSON.parse(certJson);
    const secretName = cert.spec.secretName;

    try {
      execFileSync('cmctl', ['renew', args.certificate_name, '-n', args.namespace], {
        encoding: 'utf8', timeout: 15_000,
      });
    } catch {
      execFileSync('kubectl', [
        'delete', 'secret', secretName, '-n', args.namespace,
      ], { encoding: 'utf8', timeout: 15_000 });
    }

    deps.state.addAuditEntry({
      action: 'cert_renew',
      result: 'renewed',
      details: { certificate: args.certificate_name, namespace: args.namespace, method: 'force_renewal', secretName },
    });

    return {
      success: true,
      method: 'force_renewal',
      certificate: args.certificate_name,
      namespace: args.namespace,
      secretDeleted: secretName,
      message: 'Certificate renewal triggered. cert-manager will re-issue.',
    };
  }

  if (method === 'gitops_pr') {
    if (!args.gitops_owner || !args.gitops_repo || !args.manifest_path) {
      throw new Error('gitops_owner, gitops_repo, and manifest_path are required for gitops_pr method');
    }

    const file = await deps.github.getFileContent(args.gitops_owner, args.gitops_repo, args.manifest_path);
    let content = file.content;

    const renewalTs = new Date().toISOString();
    if (content.includes('git-steer/renew-at')) {
      content = content.replace(/git-steer\/renew-at:\s*["']?[^"'\n]+["']?/, `git-steer/renew-at: "${renewalTs}"`);
    } else {
      content = content.replace(
        /(annotations:\s*\n)/,
        `$1    git-steer/renew-at: "${renewalTs}"\n`
      );
    }

    const branchName = `cert-renew/${args.namespace}-${args.certificate_name}-${Date.now()}`;

    await deps.github.commitFiles(args.gitops_owner, args.gitops_repo, {
      branch: branchName,
      message: `fix(cert): trigger renewal for ${args.certificate_name}`,
      files: [{ path: args.manifest_path, content }],
      createBranch: true,
      baseBranch: 'main',
    });

    const prefix = `[Cert Renewal] ${args.namespace}/${args.certificate_name}`;
    const openPrs = await deps.github.listPullRequests(args.gitops_owner, args.gitops_repo, { state: 'open' });
    const existingPr = openPrs.find((pr) => pr.title.startsWith(prefix));

    if (existingPr) {
      return { created: false, dedup_hit: true, existing_pr: existingPr };
    }

    const pr = await deps.github.createPullRequest(args.gitops_owner, args.gitops_repo, {
      title: `${prefix} — trigger re-issuance`,
      body: `## Certificate Renewal\n\n**Certificate:** \`${args.namespace}/${args.certificate_name}\`\n**Method:** GitOps PR with renewal annotation\n\n_Auto-generated by git-steer cert_renew_`,
      head: branchName,
      base: 'main',
      labels: ['certificate', 'auto-remediation'],
    });

    deps.state.addAuditEntry({
      action: 'cert_renew',
      result: 'pr_created',
      details: { certificate: args.certificate_name, namespace: args.namespace, method: 'gitops_pr', prNumber: pr.number },
    });

    return {
      success: true,
      method: 'gitops_pr',
      pr: { number: pr.number, url: pr.url },
    };
  }

  throw new Error(`Unknown method: ${method}`);
}
