import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import solc from 'solc';
import ganache from 'ganache';
import { BrowserProvider, ContractFactory, Contract } from 'ethers';

test('Registry v2 contract lifecycle: register, validate, dispute, revise', async () => {
  // Compile contract
  const source = await readFile(new URL('./chain/Registry.sol', import.meta.url), 'utf8');
  const build = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: { 'Registry.sol': { content: source } },
    settings: { evmVersion: 'shanghai', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } }
  })));
  const artifact = build.contracts?.['Registry.sol']?.Registry;
  assert(artifact, 'Solidity compilation failed');

  // In-process Ganache provider
  const ganacheProvider = ganache.provider({ logging: { quiet: true } });
  const provider = new BrowserProvider(ganacheProvider);
  const reporter = await provider.getSigner(0);
  const validator1 = await provider.getSigner(1);
  const validator2 = await provider.getSigner(2);
  const disputer = await provider.getSigner(3);

  // Deploy
  const factory = new ContractFactory(artifact.abi, artifact.evm.bytecode.object, reporter);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();

  // Test 1: Register
  const c1 = '0x' + '11'.repeat(32);
  const root1 = '0x' + 'aa'.repeat(32);
  await (await contract['register(bytes32,bytes32,uint8)'](c1, root1, 0)).wait();

  const recordedTime = await contract.recordedAt(c1);
  assert(recordedTime > 0n);

  let rep1 = await contract.getReport(c1);
  assert.equal(rep1.reporter, await reporter.getAddress());
  assert.equal(Number(rep1.status), 0); // Submitted

  // Test 2: Validation by validator1 and validator2
  const cValidator1 = new Contract(address, artifact.abi, validator1);
  await (await cValidator1.validate(c1)).wait();

  rep1 = await contract.getReport(c1);
  assert.equal(Number(rep1.validations), 1);
  assert.equal(Number(rep1.status), 0); // Still Submitted

  const cValidator2 = new Contract(address, artifact.abi, validator2);
  await (await cValidator2.validate(c1)).wait();

  rep1 = await contract.getReport(c1);
  assert.equal(Number(rep1.validations), 2);
  assert.equal(Number(rep1.status), 1); // Validated (>= 2 validations)

  // Test 3: Duplicate action rejected
  await assert.rejects(async () => {
    const tx = await cValidator1.validate(c1);
    await tx.wait();
  }, (err) => err.code === 'CALL_EXCEPTION' || /revert|Already acted/i.test(err.message));

  // Test 4: Dispute
  const cDisputer = new Contract(address, artifact.abi, disputer);
  const reasonHash = '0x' + '99'.repeat(32);
  await (await cDisputer.dispute(c1, reasonHash)).wait();

  rep1 = await contract.getReport(c1);
  assert.equal(Number(rep1.disputes), 1);

  // Test 5: Non-owner revise rejected
  const c2 = '0x' + '22'.repeat(32);
  const root2 = '0x' + 'bb'.repeat(32);
  await assert.rejects(async () => {
    const tx = await cValidator1.revise(c1, c2, root2);
    await tx.wait();
  }, (err) => err.code === 'CALL_EXCEPTION' || /revert|Only original reporter/i.test(err.message));

  // Test 6: Owner revise
  await (await contract.revise(c1, c2, root2)).wait();

  rep1 = await contract.getReport(c1);
  assert.equal(Number(rep1.status), 3); // Superseded
  assert.equal(rep1.supersededBy, c2);

  const rep2 = await contract.getReport(c2);
  assert.equal(Number(rep2.status), 0); // Submitted
  assert.equal(rep2.evidenceRoot, root2);

  // Test 7: History
  const history = await contract.historyOf(await reporter.getAddress());
  assert.equal(history.length, 2);
  assert.equal(history[0], c1);
  assert.equal(history[1], c2);

  await provider.destroy();
});
