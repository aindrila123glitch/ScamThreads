import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {Contract,JsonRpcProvider} from 'ethers';
import {verifyProof} from '../merkle.mjs';

const [file,address,rpc='http://127.0.0.1:8545',proofFile]=process.argv.slice(2);
if(!file||!address)throw Error('Usage: node chain/verify.mjs REPORT CONTRACT_ADDRESS [RPC_URL] [PROOF_FILE]');

const bytes=await readFile(file);
const commitment='0x'+createHash('sha256').update(bytes).digest('hex');
const provider=new JsonRpcProvider(rpc);
const STATUS_NAMES=['Submitted','Validated','Disputed','Superseded'];

try{
  const contract=new Contract(address,[
    'function recordedAt(bytes32) view returns(uint256)',
    'function getReport(bytes32) view returns(tuple(address reporter, uint64 timestamp, bytes32 evidenceRoot, uint8 category, uint8 status, bytes32 supersededBy, uint32 validations, uint32 disputes))'
  ],provider);

  const timestamp=await contract.recordedAt(commitment);
  const verified=timestamp!==0n;
  let reportDetails=null;
  let proofVerified=null;

  if(verified){
    try{
      const rep=await contract.getReport(commitment);
      reportDetails={
        reporter:rep.reporter,
        timestamp:rep.timestamp.toString(),
        evidenceRoot:rep.evidenceRoot,
        category:Number(rep.category),
        status:STATUS_NAMES[Number(rep.status)]||'Unknown',
        supersededBy:rep.supersededBy!=='0x0000000000000000000000000000000000000000000000000000000000000000'?rep.supersededBy:null,
        validations:Number(rep.validations),
        disputes:Number(rep.disputes)
      };

      if(proofFile){
        const proofData=JSON.parse(await readFile(proofFile,'utf8'));
        const cleanRoot = rep.evidenceRoot.startsWith('0x') ? rep.evidenceRoot.slice(2) : rep.evidenceRoot;
        proofVerified=verifyProof(proofData.leaf, proofData.proof, cleanRoot);
      }
    }catch{}
  }

  console.log(JSON.stringify({
    commitment,
    verified,
    registeredAt:timestamp.toString(),
    report:reportDetails,
    proofVerified
  },null,2));

  if(!verified||(proofFile&&proofVerified===false))process.exitCode=1;
}finally{provider.destroy();}
