const RANK = { allow: 1, require_approval: 2, deny: 3 };

function toBigIntString(v, name) {
  if (v === undefined || v === null || v === '') return null;
  const s = String(v);
  if (!/^\d+$/.test(s)) throw new Error(`${name} must be an unsigned integer string.`);
  return BigInt(s);
}

function domainMatches(candidate, blocked) {
  const c = String(candidate || '').toLowerCase().replace(/\.$/, '');
  const b = String(blocked || '').toLowerCase().replace(/\.$/, '');
  return c === b || c.endsWith(`.${b}`);
}

function conditionsMatch(rule, action) {
  const c = rule.conditions || {};
  if (c.currency && String(action.currency || '').toUpperCase() !== String(c.currency).toUpperCase()) return false;

  if (c.amount_minor_gt !== undefined) {
    const amount = toBigIntString(action.amount_minor, 'amount_minor');
    if (amount === null || amount <= BigInt(c.amount_minor_gt)) return false;
  }
  if (c.aggregate_24h_minor_gt !== undefined) {
    const amount = toBigIntString(action.aggregate_24h_minor, 'aggregate_24h_minor');
    if (amount === null || amount <= BigInt(c.aggregate_24h_minor_gt)) return false;
  }
  if (Array.isArray(c.recipients)) {
    if (!c.recipients.includes(String(action.recipient || ''))) return false;
  }
  if (Array.isArray(c.domains)) {
    if (!c.domains.some(d => domainMatches(action.domain, d))) return false;
  }
  if (c.max_depth !== undefined && action.operation === 'spawn_child_agent') {
    const depth = Number(action.depth ?? 1);
    if (depth > Number(c.max_depth)) return false;
  }
  return true;
}

export function evaluateRoot(document, action) {
  if (!document || document.protocol !== 'SovereignRoot') throw new Error('Not a SovereignRoot policy.');
  if (document.semantics?.model !== 'deny-overrides') throw new Error('Unsupported policy semantics.');
  if (!action?.category || !action?.operation) throw new Error('Action requires category and operation.');

  const applicable = (document.rules || []).filter(rule =>
    rule.category === action.category && rule.operation === action.operation && conditionsMatch(rule, action)
  );

  // Explicit handling for delegation ceilings: an allowed child-spawn rule with a max depth
  // does not imply permission beyond that depth.
  if (action.operation === 'spawn_child_agent') {
    const spawnRule = (document.rules || []).find(r => r.id === 'agents.spawn');
    if (spawnRule?.effect === 'allow' && spawnRule.conditions?.max_depth !== undefined) {
      const depth = Number(action.depth ?? 1);
      if (depth > Number(spawnRule.conditions.max_depth)) {
        return { decision: 'deny', reason: 'Child-agent depth exceeds root ceiling.', matched_rules: ['agents.spawn'] };
      }
    }
  }

  if (!applicable.length) {
    return {
      decision: document.semantics.unknown_action,
      reason: 'No root rule matched; applying unknown_action.',
      matched_rules: []
    };
  }

  const winner = applicable.reduce((best, r) => RANK[r.effect] > RANK[best.effect] ? r : best, applicable[0]);
  return {
    decision: winner.effect,
    reason: winner.description,
    matched_rules: applicable.map(r => r.id),
    winning_rule: winner.id
  };
}

export function intersectDecision(rootDecision, downstreamDecision) {
  if (!RANK[rootDecision] || !RANK[downstreamDecision]) throw new Error('Unknown decision value.');
  return RANK[rootDecision] >= RANK[downstreamDecision] ? rootDecision : downstreamDecision;
}
