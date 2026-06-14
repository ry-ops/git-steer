/**
 * Append rows to an append-only JSONL file in the git-steer-state repo
 * (read existing -> append -> write), creating the file if it doesn't exist.
 * Shared by the CLI VEX writers so they feed the same vex.jsonl ledger the
 * StateManager (MCP) writes.
 */
export async function appendJsonl(octokit, owner, stateRepo, path, entries) {
  if (!entries || entries.length === 0) return 0;

  let existing = '';
  let sha;
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
      owner, repo: stateRepo, path,
    });
    sha = data.sha;
    existing = Buffer.from(data.content, 'base64').toString('utf-8');
  } catch { /* file doesn't exist yet */ }

  const newLines = entries.map((e) => JSON.stringify(e)).join('\n');
  const prefix = existing && !existing.endsWith('\n') ? existing + '\n' : existing;
  const content = prefix + newLines + '\n';

  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner, repo: stateRepo, path,
    message: `vex-ledger: +${entries.length} change(s)`,
    content: Buffer.from(content).toString('base64'),
    ...(sha ? { sha } : {}),
  });
  return entries.length;
}
