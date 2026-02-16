/**
 * CI Changelog Sync
 *
 * Runs in GitHub Actions (daily via heartbeat).
 * Scans all managed repos for recent activity (merged PRs, releases),
 * generates changelog entries, and commits them to the blog repo.
 *
 * Env vars:
 *   GH_TOKEN      - GitHub installation token
 *   STATE_OWNER   - State repo owner (default: ry-ops)
 *   STATE_REPO    - State repo name (default: git-steer-state)
 *   BLOG_OWNER    - Blog repo owner (default: ry-ops)
 *   BLOG_REPO     - Blog repo name (default: blog)
 *   LOOKBACK_HOURS - Hours to look back for activity (default: 25, slightly > 24 for overlap)
 */

import { Octokit } from 'octokit';

const token = process.env.GH_TOKEN;
if (!token) {
  console.error('GH_TOKEN environment variable is required');
  process.exit(1);
}

const STATE_OWNER = process.env.STATE_OWNER || 'ry-ops';
const STATE_REPO = process.env.STATE_REPO || 'git-steer-state';
const BLOG_OWNER = process.env.BLOG_OWNER || 'ry-ops';
const BLOG_REPO = process.env.BLOG_REPO || 'blog';
const LOOKBACK_HOURS = parseInt(process.env.LOOKBACK_HOURS || '25', 10);

const octokit = new Octokit({ auth: token });

// ===== Category mapping by repo =====
const REPO_CATEGORIES = {
  'aiana': 'AI & ML',
  'qdrant-fabric': 'AI & ML',
  'DriveIQ': 'AI & ML',
  'ATSFlow': 'AI & ML',
  'unifi-mcp-server': 'Engineering',
  'git-steer': 'Engineering',
  'git-steer-state': 'Security',
  'blog': 'Engineering',
  'building-serverless-website-github-cloudflare': 'Engineering',
  'getting-started-docker-containers': 'Engineering',
};

// ===== Detect changelog entry type from PR =====
function classifyPR(pr) {
  const title = (pr.title || '').toLowerCase();
  const labels = (pr.labels || []).map((l) => l.name.toLowerCase());
  const body = (pr.body || '').toLowerCase();

  // Security fixes
  if (
    title.includes('cve') ||
    title.includes('security') ||
    title.includes('dependabot') ||
    title.includes('vulnerability') ||
    labels.some((l) => l.includes('security') || l.includes('dependabot')) ||
    body.includes('cve-')
  ) {
    return { type: 'fix', category: 'Security' };
  }

  // Bug fixes
  if (
    title.startsWith('fix:') ||
    title.startsWith('fix(') ||
    title.startsWith('bugfix') ||
    title.includes('bug fix') ||
    labels.some((l) => l === 'bug' || l === 'bugfix')
  ) {
    return { type: 'fix' };
  }

  // Features
  if (
    title.startsWith('feat:') ||
    title.startsWith('feat(') ||
    title.startsWith('feature') ||
    title.includes('add ') ||
    title.includes('implement') ||
    title.includes('introduce') ||
    labels.some((l) => l === 'feature' || l === 'enhancement')
  ) {
    return { type: 'feature' };
  }

  // Documentation
  if (
    title.startsWith('docs:') ||
    title.startsWith('doc:') ||
    title.includes('readme') ||
    title.includes('documentation') ||
    labels.some((l) => l === 'documentation' || l === 'docs')
  ) {
    return { type: 'improvement', category: 'Docs' };
  }

  // Default to improvement
  return { type: 'improvement' };
}

// ===== Calculate relevance score =====
function calculateRelevance(pr, classification) {
  let base = 0.6;

  // Security fixes are high relevance
  if (classification.category === 'Security') base = 0.85;

  // Features are high relevance
  if (classification.type === 'feature') base = 0.8;

  // Boost for larger PRs (more changes = more significant)
  if (pr.additions + pr.deletions > 500) base = Math.min(base + 0.1, 0.95);
  if (pr.additions + pr.deletions > 100) base = Math.min(base + 0.05, 0.95);

  // Boost for PRs with many reviews/comments
  if ((pr.comments || 0) > 3) base = Math.min(base + 0.05, 0.95);

  return Math.round(base * 100) / 100;
}

// ===== Generate slug from title =====
function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60);
}

// ===== Generate a readable title =====
function generateTitle(pr, repoName) {
  let title = pr.title || '';

  // Strip conventional commit prefixes
  title = title.replace(/^(feat|fix|docs|chore|refactor|ci|style|perf|test)\s*(\([^)]*\))?\s*:\s*/i, '');

  // Capitalize first letter
  title = title.charAt(0).toUpperCase() + title.slice(1);

  // Add repo context if not already in the title
  const repoShort = repoName.split('/').pop();
  if (!title.toLowerCase().includes(repoShort.toLowerCase())) {
    title = `${title} (${repoShort})`;
  }

  return title;
}

// ===== Generate entry body =====
function generateBody(pr, repoName, classification) {
  const lines = [];

  // Main description — extract first meaningful paragraph from PR body
  if (pr.body) {
    const cleaned = pr.body
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/^#+ .+$/gm, '')
      .trim();
    const firstPara = cleaned.split(/\n\n/)[0]?.trim();
    if (firstPara && firstPara.length > 20 && firstPara.length < 500) {
      lines.push(firstPara);
    }
  }

  // Fallback description if no good body
  if (lines.length === 0) {
    if (classification.type === 'fix' && classification.category === 'Security') {
      lines.push(`Security patch applied to ${repoName} — dependency vulnerabilities remediated.`);
    } else if (classification.type === 'fix') {
      lines.push(`Bug fix merged in ${repoName}: ${pr.title}.`);
    } else if (classification.type === 'feature') {
      lines.push(`New feature shipped in ${repoName}: ${pr.title}.`);
    } else {
      lines.push(`Update to ${repoName}: ${pr.title}.`);
    }
  }

  // Add PR link
  lines.push('');
  lines.push(`[View PR #${pr.number}](${pr.html_url})`);

  return lines.join('\n');
}

// ===== Fetch managed repos =====
async function getManagedRepos() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'config/managed-repos.yaml' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    const repos = content.match(/^\s*-\s+(.+)$/gm);
    if (repos) {
      return repos.map((r) => {
        const name = r.replace(/^\s*-\s+/, '').trim();
        const [owner, repo] = name.split('/');
        return { owner, name: repo, fullName: name };
      });
    }
  } catch {
    // fallback
  }

  // Try installation repos (works with GitHub App tokens)
  try {
    const { data } = await octokit.request('GET /installation/repositories');
    return data.repositories
      .filter((r) => !r.archived)
      .map((r) => ({ owner: r.owner.login, name: r.name, fullName: r.full_name }));
  } catch {
    // Fallback for PAT: list user/org repos
    const { data } = await octokit.request('GET /users/{username}/repos', {
      username: STATE_OWNER,
      type: 'owner',
      sort: 'updated',
      per_page: 100,
    });
    return data
      .filter((r) => !r.archived)
      .map((r) => ({ owner: r.owner.login, name: r.name, fullName: r.full_name }));
  }
}

// ===== Fetch merged PRs since cutoff =====
async function getRecentMergedPRs(repo, since) {
  try {
    const { data: prs } = await octokit.request(
      'GET /repos/{owner}/{repo}/pulls',
      {
        owner: repo.owner,
        repo: repo.name,
        state: 'closed',
        sort: 'updated',
        direction: 'desc',
        per_page: 30,
      }
    );

    return prs.filter((pr) => {
      if (!pr.merged_at) return false;
      return new Date(pr.merged_at) >= since;
    });
  } catch (err) {
    console.error(`  Warning: ${repo.fullName}: ${err.message || 'failed to fetch PRs'}`);
    return [];
  }
}

// ===== Get existing changelog filenames to avoid duplicates =====
async function getExistingEntries() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: BLOG_OWNER, repo: BLOG_REPO, path: 'src/content/changelog' }
    );
    return new Set(data.map((f) => f.name));
  } catch {
    return new Set();
  }
}

// ===== Commit a changelog entry to the blog repo =====
async function commitEntry(filename, content) {
  // Check if file already exists
  let sha;
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: BLOG_OWNER, repo: BLOG_REPO, path: `src/content/changelog/${filename}` }
    );
    sha = data.sha;
    // File exists — skip to avoid overwriting
    console.log(`  Skipping ${filename} (already exists)`);
    return false;
  } catch {
    // File doesn't exist — good, we'll create it
  }

  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: BLOG_OWNER,
    repo: BLOG_REPO,
    path: `src/content/changelog/${filename}`,
    message: `changelog: ${filename.replace('.md', '')}`,
    content: Buffer.from(content).toString('base64'),
  });

  return true;
}

// ===== Build a markdown changelog entry =====
function buildEntry(pr, repoFullName, classification) {
  const mergedAt = new Date(pr.merged_at);
  const dateStr = mergedAt.toISOString().split('T')[0];
  const title = generateTitle(pr, repoFullName);
  const category = classification.category || REPO_CATEGORIES[repoFullName.split('/').pop()] || 'Engineering';
  const relevance = calculateRelevance(pr, classification);
  const body = generateBody(pr, repoFullName, classification);

  const slug = slugify(title);
  const filename = `${dateStr}-${slug}.md`;

  const frontmatter = [
    '---',
    `title: "${title.replace(/"/g, '\\"')}"`,
    `date: ${mergedAt.toISOString()}`,
    `type: ${classification.type}`,
    `category: ${category}`,
    `relevance: ${relevance}`,
    '---',
  ].join('\n');

  const content = `${frontmatter}\n\n${body}\n`;

  return { filename, content };
}

// ===== Main =====
async function main() {
  console.log('=== git-steer Changelog Sync ===\n');

  const since = new Date(Date.now() - LOOKBACK_HOURS * 60 * 60 * 1000);
  console.log(`Looking back ${LOOKBACK_HOURS}h (since ${since.toISOString()})\n`);

  console.log('Fetching managed repos...');
  const repos = await getManagedRepos();
  console.log(`Found ${repos.length} repos\n`);

  console.log('Fetching existing changelog entries...');
  const existing = await getExistingEntries();
  console.log(`Found ${existing.size} existing entries\n`);

  console.log('Scanning for recent activity...');
  const entries = [];

  for (const repo of repos) {
    const prs = await getRecentMergedPRs(repo, since);
    if (prs.length > 0) {
      process.stdout.write(`  ${repo.fullName}: ${prs.length} merged PRs\n`);
      for (const pr of prs) {
        const classification = classifyPR(pr);
        const entry = buildEntry(pr, repo.fullName, classification);

        // Skip if similar filename already exists
        if (existing.has(entry.filename)) {
          console.log(`    Skip: ${entry.filename} (exists)`);
          continue;
        }

        entries.push(entry);
        console.log(`    Add: ${entry.filename} [${classification.type}]`);
      }
    } else {
      process.stdout.write(`  ${repo.fullName}: no activity\n`);
    }
  }

  console.log(`\n${entries.length} new changelog entries to create\n`);

  if (entries.length === 0) {
    console.log('Nothing to do. Done!');
    return;
  }

  console.log('Committing entries to blog repo...');
  let created = 0;
  for (const entry of entries) {
    const ok = await commitEntry(entry.filename, entry.content);
    if (ok) {
      console.log(`  Created: ${entry.filename}`);
      created++;
    }
  }

  console.log(`\nDone! Created ${created} changelog entries.`);
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
