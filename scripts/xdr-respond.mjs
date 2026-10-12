import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';
import { respond } from '../xdr/brute-force/respond.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MODULE_KEY = 'brute-force';
const PROPOSALS_PATH = join(
  ROOT,
  'xdr',
  'brute-force',
  'deny-rule-proposals.json',
);

async function addDenyRuleProposal(rule) {
  let proposals = [];

  try {
    proposals = JSON.parse(
      await readFile(PROPOSALS_PATH, 'utf8'),
    );
    if (!Array.isArray(proposals)) {
      throw new Error('invalid_proposal_store');
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const existingIndex = proposals.findIndex(
    (item) => item.id === rule.id,
  );

  if (existingIndex >= 0) {
    proposals[existingIndex] = rule;
  } else {
    proposals.push(rule);
  }

  await mkdir(dirname(PROPOSALS_PATH), { recursive: true });
  await writeFile(
    PROPOSALS_PATH,
    `${JSON.stringify(proposals, null, 2)}\n`,
    'utf8',
  );
}

const result = await runXdr({
  root: ROOT,
  moduleKey: MODULE_KEY,
});

const fixture = JSON.parse(
  await readFile(
    join(ROOT, 'xdr', 'fixtures', `${MODULE_KEY}.json`),
    'utf8',
  ),
);

const alertsById = new Map(
  fixture.alerts.map((alert) => [alert.id, alert]),
);

const summary = {
  total: result.decisions.length,
  proposalsAdded: 0,
  notEligible: 0,
  errors: 0,
};

for (const decision of result.decisions) {
  const alert = alertsById.get(decision.alertId);

  if (!alert) {
    summary.errors += 1;
    continue;
  }

  try {
    const outcome = await respond({
      alert,
      decision: {
        action: decision.action,
        confidence: decision.confidence,
        reason: decision.reason,
      },
      addDenyRule: addDenyRuleProposal,
    });

    if (outcome.ruleAdded) {
      summary.proposalsAdded += 1;
    } else {
      summary.notEligible += 1;
    }
  } catch {
    summary.errors += 1;
  }
}

console.log(JSON.stringify(summary, null, 2));