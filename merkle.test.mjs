import test from 'node:test';
import assert from 'node:assert/strict';
import { leaf, root, proof, verifyProof, buildTree, hashPair } from './merkle.mjs';

test('merkle tree produces consistent root for identical leaves', () => {
  const leaves = ['a', 'b', 'c', 'd'].map(s => leaf({ id: s, finding: 'Finding ' + s, source: 'TestSource' }));
  const r1 = root(leaves);
  const r2 = root(leaves);
  assert.equal(r1, r2);
  assert.equal(r1.length, 64);
});

test('merkle proof verifies authentic leaf at correct index', () => {
  const items = [
    { id: 'E1', finding: 'Punycode domain', source: 'Lexical rules' },
    { id: 'E2', finding: 'Missing HSTS', source: 'Passive URL/HTTP scan' },
    { id: 'E3', finding: 'Password input targets external host', source: 'Passive URL/HTTP scan' },
    { id: 'E4', finding: 'Known distrust match', source: 'TLS check' },
    { id: 'E5', finding: 'Urgency language', source: 'Local message rules' }
  ];
  const leaves = items.map(leaf);
  const treeRoot = root(leaves);

  for (let i = 0; i < leaves.length; i++) {
    const p = proof(leaves, i);
    assert(verifyProof(leaves[i], p, treeRoot), `Proof failed for leaf index ${i}`);
  }
});

test('merkle proof rejects tampered leaf, wrong index, or wrong root', () => {
  const items = [
    { id: 'E1', finding: 'Finding 1', source: 'Source 1' },
    { id: 'E2', finding: 'Finding 2', source: 'Source 2' },
    { id: 'E3', finding: 'Finding 3', source: 'Source 3' }
  ];
  const leaves = items.map(leaf);
  const treeRoot = root(leaves);

  const p0 = proof(leaves, 0);

  // Tampered leaf
  const tamperedLeaf = leaf({ id: 'E1', finding: 'Tampered Finding', source: 'Source 1' });
  assert.equal(verifyProof(tamperedLeaf, p0, treeRoot), false);

  // Wrong root
  const wrongRoot = '1'.repeat(64);
  assert.equal(verifyProof(leaves[0], p0, wrongRoot), false);

  // Tampered sibling in proof
  const corruptedProof = [p0[0].slice(0, 63) + (p0[0][63] === 'a' ? 'b' : 'a'), ...p0.slice(1)];
  assert.equal(verifyProof(leaves[0], corruptedProof, treeRoot), false);
});

