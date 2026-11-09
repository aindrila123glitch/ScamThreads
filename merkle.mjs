// Merkle Evidence Tree and Zero-Knowledge Proofs for Selective Disclosure
import { createHash } from 'node:crypto';

export function hashString(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

export function leaf(item) {
  if (!item || typeof item !== 'object') throw Error('Evidence item must be an object.');
  const canonical = JSON.stringify({
    id: String(item.id ?? ''),
    finding: String(item.finding ?? ''),
    source: String(item.source ?? '')
  });
  return hashString(canonical);
}

export function hashPair(a, b) {
  const [first, second] = [String(a), String(b)].sort();
  return hashString(first + second);
}

export function buildTree(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    const empty = '0'.repeat(64);
    return [[empty]];
  }
  const levels = [leaves.map(l => String(l).toLowerCase())];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashPair(current[i], current[i + 1]));
      } else {
        // Duplicate last node for odd length
        next.push(hashPair(current[i], current[i]));
      }
    }
    levels.push(next);
  }
  return levels;
}

export function root(leaves) {
  const tree = buildTree(leaves);
  return tree[tree.length - 1][0];
}

export function proof(leaves, index) {
  if (!Array.isArray(leaves) || index < 0 || index >= leaves.length) {
    throw Error('Invalid leaves array or index out of bounds.');
  }
  const tree = buildTree(leaves);
  const path = [];
  let idx = index;

  for (let level = 0; level < tree.length - 1; level++) {
    const nodes = tree[level];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : (idx + 1 < nodes.length ? idx + 1 : idx);
    path.push(nodes[siblingIdx]);
    idx = Math.floor(idx / 2);
  }
  return path;
}

export function verifyProof(leafHash, proofArray, expectedRoot) {
  if (!leafHash || !Array.isArray(proofArray) || !expectedRoot) return false;
  let current = String(leafHash).toLowerCase();
  for (const sibling of proofArray) {
    current = hashPair(current, sibling);
  }
  return current.toLowerCase() === String(expectedRoot).toLowerCase();
}

