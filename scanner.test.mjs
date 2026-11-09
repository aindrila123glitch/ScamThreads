import test from 'node:test';
import assert from 'node:assert/strict';
import {scan,normalize,publicIPv4} from './scanner.mjs';
import {fixtures} from './fixtures.mjs';
const expected=['High Risk','Suspicious','Confirmed Malicious','Low Risk','Low Risk','Low Risk','Suspicious','Suspicious'];
for(const [i,url] of Object.keys(fixtures).entries())test(url,async()=>{
  assert.equal((await scan({url})).verdict,expected[i]);
});
test('blocks internal ranges and non-default ports',async()=>{
  for(const ip of ['127.0.0.1','10.1.2.3','169.254.169.254','192.168.1.1','100.64.0.1','::1'])assert.equal(publicIPv4(ip),false);
  assert.throws(()=>normalize('http://example.com:8080'));
  assert.throws(()=>normalize('https://user:pass@example.com'));
  const result=await scan({url:'http://127.0.0.1'});
  assert.equal(result.verdict,'Inconclusive');
  assert.match(result.limits[0],/blocked/);
});
test('message urgency is not confirmation',async()=>{
  const report=await scan({message:'Urgent: send your password and application fee.'});
  assert.equal(report.verdict,'Suspicious');
  assert.equal(report.messageSignals.length,3);
});
