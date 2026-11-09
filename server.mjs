import http from 'node:http';
import {readFile,appendFile,writeFile} from 'node:fs/promises';
import {createHash,createHmac,randomUUID} from 'node:crypto';
import {scan,normalize} from './scanner.mjs';
import {fixtures} from './fixtures.mjs';
import {validateExplanation,watch} from './intelligence.mjs';
import {fetchFile,inspectFile} from './filecheck.mjs';
import {leaf,root,proof,verifyProof} from './merkle.mjs';
import {deterministicExplanation} from './explain.mjs';

const local=name=>new URL(name,import.meta.url);
async function load(name,fallback){try{return await readFile(local(name),'utf8');}catch(error){if(error.code==='ENOENT')return fallback;throw error;}}
const distrust={...JSON.parse(await load('ca-incidents.json','{}')),...JSON.parse(await load('distrust.json','{}'))};
const brands=JSON.parse(await load('brands.json','[]'));
const known=new Set();
const intelRaw=(await load('intel/urlhaus.txt',''))||(await load('urlhaus.txt',''));
for(const line of intelRaw.split(/\r?\n/)){
  if(!/^https?:\/\//i.test(line))continue;
  try{known.add(normalize(line).href);}catch{}
}
const malwareHashes=new Set();
for(const line of (await load('malware-hashes.txt','')).split(/\r?\n/)){
  const trimmed=line.trim();
  if(trimmed && !trimmed.startsWith('#') && /^[0-9a-f]{64}$/i.test(trimmed)) malwareHashes.add(trimmed.toLowerCase());
}
const reports=(await load('reports.jsonl','')).split('\n').filter(Boolean).map(JSON.parse);
let salt=process.env.CAMPAIGN_KEY || (await load('.campaign-key',''));
if(!salt){
  salt=randomUUID();
  try{
    await writeFile(local('.campaign-key'),salt,{flag:'wx'});
  }catch{
    // Read-only filesystem in serverless environments (e.g. Vercel)
  }
}
const hash=value=>createHash('sha256').update(value).digest('hex');
const indicator=value=>typeof value==='string'&&value?createHmac('sha256',salt).update(value).digest('hex'):null;
const json=(res,status,data)=>{
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
  res.end(JSON.stringify(data));
};
async function body(req){
  if(!String(req.headers['content-type']).startsWith('application/json'))throw Error('Expected application/json.');
  let size=0;
  const chunks=[];
  for await(const chunk of req){
    size+=chunk.length;
    if(size>65536)throw Error('Request exceeds 64 KiB.');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}
async function registry(){
  const config=JSON.parse(await load('chain/deployment.json','null')) || {
    rpc: process.env.RPC_URL || 'http://127.0.0.1:8545',
    address: '0x0000000000000000000000000000000000000000',
    abi: []
  };
  const {Contract,JsonRpcProvider}=await import('ethers');
  const provider=new JsonRpcProvider(config.rpc);
  return {Contract,provider,config};
}
const isVercel=Boolean(process.env.VERCEL);
const port=Number(process.env.SCAMTHREADS_PORT || 8787);
if(!Number.isInteger(port)||port<1024||port>65535)throw Error('SCAMTHREADS_PORT must be between 1024 and 65535.');
const hosts=[`127.0.0.1:${port}`,`localhost:${port}`];
let active=0;
export const server=http.createServer(async(req,res)=>{
  try{
    const path=(req.url||'/').split('?')[0];
    const host=req.headers.host || '';
    const origin=req.headers.origin;
    const isLocalHost=hosts.includes(host);
    const isVercelHost=isVercel || host.endsWith('.vercel.app') || host.includes('vercel');
    if(!isLocalHost && !isVercelHost)
      return json(res,403,{error:'Authorized host required.'});
    if(origin && !/^chrome-extension:\/\/[a-p]{32}$/.test(origin) && !hosts.map(h=>'http://'+h).includes(origin) && !origin.includes('vercel.app'))
      return json(res,403,{error:'Origin blocked.'});
    if(origin?.startsWith('chrome-extension://')){
      if(!['/api/scan','/api/threats'].includes(path))return json(res,403,{error:'Dashboard only.'});
      res.setHeader('Access-Control-Allow-Origin',origin);
      res.setHeader('Vary','Origin');
      res.setHeader('Access-Control-Allow-Headers','Content-Type');
      res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');
    }
    if(req.method==='OPTIONS')return json(res,204,null);
    if(req.method==='GET'){
      if(path==='/api/threats')return json(res,200,{urls:['https://forms-scam.example/login',...[...known].slice(0,999)],distrust});
      if(path==='/api/fixtures')return json(res,200,Object.keys(fixtures));
      if(path==='/api/campaigns')return json(res,200,reports.map(({id,time,verdict,links})=>({id,time,verdict,links})));
      if(path==='/api/eval'){
        const evalData=JSON.parse(await load('eval/results.json','null'));
        return json(res,200,evalData||{status:'Run npm run eval first'});
      }
      const files={
        '/':['public/index.html','text/html'],
        '/index.html':['public/index.html','text/html'],
        '/link':['public/link.html','text/html'],
        '/link.html':['public/link.html','text/html'],
        '/message':['public/message.html','text/html'],
        '/message.html':['public/message.html','text/html'],
        '/file':['public/file.html','text/html'],
        '/file.html':['public/file.html','text/html'],
        '/qr':['public/qr.html','text/html'],
        '/qr.html':['public/qr.html','text/html'],
        '/reports':['public/reports.html','text/html'],
        '/reports.html':['public/reports.html','text/html'],
        '/watch':['public/watch.html','text/html'],
        '/watch.html':['public/watch.html','text/html'],
        '/accuracy':['public/accuracy.html','text/html'],
        '/accuracy.html':['public/accuracy.html','text/html'],
        '/help':['public/help.html','text/html'],
        '/help.html':['public/help.html','text/html'],
        '/about':['public/about.html','text/html'],
        '/about.html':['public/about.html','text/html'],
        '/shared.js':['public/shared.js','text/javascript'],
        '/app.js':['public/app.js','text/javascript'],
        '/style.css':['public/style.css','text/css'],
        '/favicon.png':['extension/icons/32.png','image/png'],
        '/vendor/jsqr.js':['public/vendor/jsqr.js','text/javascript']
      };
      if(path.startsWith('/pages/') && path.endsWith('.js') && !path.includes('..')){
        try{
          const content=await readFile(local('public'+path));
          res.writeHead(200,{'Content-Type':'text/javascript; charset=utf-8','Content-Security-Policy':"default-src 'self'; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"});
          return res.end(content);
        }catch{
          return json(res,404,{error:'Not found'});
        }
      }
      if(!Object.hasOwn(files,path))return json(res,404,{error:'Not found'});
      const [file,mime]=files[path];
      res.writeHead(200,{'Content-Type':mime+'; charset=utf-8','Content-Security-Policy':"default-src 'self'; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"});
      return res.end(await readFile(local(file)));
    }
    if(req.method!=='POST')return json(res,405,{error:'Method not allowed'});
    if(path==='/api/file'){
      if(origin?.startsWith('chrome-extension://'))return json(res,403,{error:'Dashboard only.'});
      if(active>=4)return json(res,429,{error:'Scanner busy. Retry shortly.'});
      active++;
      try{
        let size=0;
        const chunks=[];
        for await(const chunk of req){
          size+=chunk.length;
          if(size>25*1024*1024)throw Error('File exceeds 25 MiB cap.');
          chunks.push(chunk);
        }
        const name=decodeURIComponent(String(req.headers['x-filename']||'uploaded-file'));
        const bytes=Buffer.concat(chunks);
        const result=await inspectFile({bytes,name,size:bytes.length,truncated:false},malwareHashes);
        return json(res,200,result);
      }finally{active--;}
    }
    const input=await body(req);
    if(path==='/api/download'){
      if(origin?.startsWith('chrome-extension://'))return json(res,403,{error:'Dashboard only.'});
      if(active>=4)return json(res,429,{error:'Scanner busy. Retry shortly.'});
      active++;
      try{
        const fetched=await fetchFile(String(input.url||''));
        const result=await inspectFile(fetched,malwareHashes);
        return json(res,200,result);
      }finally{active--;}
    }
    if(path==='/api/scan'){
      if(active>=4)return json(res,429,{error:'Scanner busy. Retry shortly.'});
      active++;
      try{
        const result=await scan({...input,known,distrust,brands,deep:input.deep===true&&!origin?.startsWith('chrome-extension://')});
        result.explanationSource='Rule-based';
        if(process.env.OLLAMA_MODEL && !origin?.startsWith('chrome-extension://')){
          try{
            const response=await fetch('http://127.0.0.1:11434/api/generate',{
              method:'POST',headers:{'Content-Type':'application/json'},signal:AbortSignal.timeout(10000),
              body:JSON.stringify({model:process.env.OLLAMA_MODEL,stream:false,options:{num_predict:180},
                system:'Explain the scanner evidence. One short sentence per line. End each line with one or more supplied evidence IDs in brackets, such as [E1, E2]. No headings or unsupported claims.',
                prompt:JSON.stringify({verdict:result.verdict,findings:result.evidence.map(({id,finding})=>({id,finding}))})})
            });
            if(!response.ok)throw Error('Model unavailable');
            const candidate=validateExplanation(String((await response.json()).response??'').slice(0,2000),new Set(result.evidence.map(item=>item.id)));
            if(candidate){
              result.explanation=candidate;
              result.explanationSource='Local model ('+process.env.OLLAMA_MODEL+')';
            }else{
              result.explanation=deterministicExplanation(result);
            }
          }catch{
            result.explanation=deterministicExplanation(result);
          }
        }else{
          result.explanation=deterministicExplanation(result);
        }
        return json(res,200,result);
      }finally{active--;}
    }
    if(path==='/api/watch'){
      if(active>=4)return json(res,429,{error:'Scanner busy. Retry shortly.'});
      active++;
      try{return json(res,200,await watch(String(input.domain??'')));}finally{active--;}
    }
    if(path==='/api/report'){
      const {report}=input;
      if(!report || typeof report!=='object' || !Array.isArray(report.signals))throw Error('Scan report required.');
      const record={id:randomUUID(),time:new Date().toISOString(),verdict:String(report.verdict).slice(0,40),
        destination:indicator(report.destination),payment:indicator(report.payment),links:[]};
      const features={
        'Certificate fingerprint':(Array.isArray(report.certificates)?report.certificates:[]).slice(0,1).map(cert=>cert?.fingerprint),
        'Favicon fingerprint':[report.observed?.favicon],
        'Page structure':[report.observed?.structure],
        'Shared IP (weak)':[report.network?.ip],
        'Shared ASN (weak)':[report.network?.asn],
        'Shared registrar (weak)':[report.network?.registrar],
        'Shared nameserver (weak)':Array.isArray(report.network?.nameservers)?report.network.nameservers.slice(0,8):[]
      };
      record.features=Object.fromEntries(Object.entries(features).map(([key,values])=>[key,values.map(indicator).filter(Boolean)]));
      for(const previous of reports){
        const matches=[];
        if(record.destination && record.destination===previous.destination)matches.push('Exact final URL');
        if(record.payment && record.payment===previous.payment)matches.push('Exact payment identifier');
        for(const [key,values] of Object.entries(record.features))
          if(values.some(value=>previous.features?.[key]?.includes(value)))matches.push(key);
        if(matches.length)record.links.push({report:previous.id,matches});
      }
      try{
        await appendFile(local('reports.jsonl'),JSON.stringify(record)+'\n');
      }catch{
        // Read-only filesystem in serverless environments
      }
      reports.push(record);
      const evidenceList=Array.isArray(report.evidence)?report.evidence:[];
      const evidenceLeaves=evidenceList.map(e=>({id:e.id,leaf:leaf(e)}));
      const evidenceRoot=root(evidenceLeaves.map(e=>e.leaf));
      const document=JSON.stringify({
        schema:2,
        id:record.id,
        nonce:randomUUID(),
        evidenceRoot:'0x'+evidenceRoot,
        evidenceLeaves,
        report,
        links:record.links
      },null,2);
      return json(res,200,{document,commitment:'0x'+hash(document),evidenceRoot:'0x'+evidenceRoot,evidenceLeaves,links:record.links});
    }
    if(path==='/api/register'){
      const {document,category=0}=input;
      if(typeof document!=='string'||!document.length)throw Error('Provide the exact report text.');
      const commitment='0x'+hash(document);
      let parsedDoc;
      try{parsedDoc=JSON.parse(document);}catch{}
      const evidenceRoot=parsedDoc?.evidenceRoot||('0x'+'0'.repeat(64));
      const {Contract,provider,config}=await registry();
      try{
        const contract=new Contract(config.address,config.abi,await provider.getSigner(0));
        let tx;
        try{
          tx=await contract['register(bytes32,bytes32,uint8)'](commitment,evidenceRoot,category);
        }catch{
          tx=await contract['register(bytes32)'](commitment);
        }
        const receipt=await tx.wait();
        const timestamp=await contract.recordedAt(commitment);
        return json(res,200,{verified:timestamp!==0n,commitment,evidenceRoot,timestamp:timestamp.toString(),
          contract:config.address,chainId:config.chainId,transaction:receipt?.hash});
      }finally{provider.destroy();}
    }
    if(path==='/api/verify'){
      const {document}=input;
      if(typeof document!=='string'||!document.length)throw Error('Provide the exact report text.');
      const commitment='0x'+hash(document);
      const {Contract,provider,config}=await registry();
      try{
        const contract=new Contract(config.address,config.abi,provider);
        const timestamp=await contract.recordedAt(commitment);
        let onChainReport=null;
        try{
          const rep=await contract.getReport(commitment);
          onChainReport={
            reporter:rep.reporter,
            timestamp:rep.timestamp.toString(),
            evidenceRoot:rep.evidenceRoot,
            category:Number(rep.category),
            status:['Submitted','Validated','Disputed','Superseded'][Number(rep.status)]||'Unknown',
            supersededBy:rep.supersededBy!=='0x0000000000000000000000000000000000000000000000000000000000000000'?rep.supersededBy:null,
            validations:Number(rep.validations),
            disputes:Number(rep.disputes)
          };
        }catch{}
        return json(res,200,{verified:timestamp!==0n,commitment,timestamp:timestamp.toString(),
          contract:config.address,chainId:config.chainId,report:onChainReport});
      }finally{provider.destroy();}
    }
    if(path==='/api/revise'){
      const {oldDocument,newDocument}=input;
      if(!oldDocument||!newDocument)throw Error('Provide oldDocument and newDocument.');
      const oldCommitment='0x'+hash(oldDocument);
      const newCommitment='0x'+hash(newDocument);
      const parsedNew=JSON.parse(newDocument);
      const newRoot=parsedNew.evidenceRoot||('0x'+'0'.repeat(64));
      const {Contract,provider,config}=await registry();
      try{
        const contract=new Contract(config.address,config.abi,await provider.getSigner(0));
        const tx=await contract.revise(oldCommitment,newCommitment,newRoot);
        const receipt=await tx.wait();
        return json(res,200,{oldCommitment,newCommitment,transaction:receipt.hash,status:'Superseded'});
      }finally{provider.destroy();}
    }
    if(path==='/api/validate'){
      const {document,commitment:rawCommitment}=input;
      const commitment=rawCommitment||('0x'+hash(document));
      const {Contract,provider,config}=await registry();
      try{
        const signer=await provider.getSigner(1);
        const contract=new Contract(config.address,config.abi,signer);
        const tx=await contract.validate(commitment);
        const receipt=await tx.wait();
        const rep=await contract.getReport(commitment);
        return json(res,200,{commitment,validations:Number(rep.validations),status:['Submitted','Validated','Disputed','Superseded'][Number(rep.status)],transaction:receipt.hash});
      }finally{provider.destroy();}
    }
    if(path==='/api/dispute'){
      const {document,commitment:rawCommitment,reason='Disputed report findings'}=input;
      const commitment=rawCommitment||('0x'+hash(document));
      const reasonHash='0x'+hash(reason);
      const {Contract,provider,config}=await registry();
      try{
        const signer=await provider.getSigner(2);
        const contract=new Contract(config.address,config.abi,signer);
        const tx=await contract.dispute(commitment,reasonHash);
        const receipt=await tx.wait();
        const rep=await contract.getReport(commitment);
        return json(res,200,{commitment,disputes:Number(rep.disputes),status:['Submitted','Validated','Disputed','Superseded'][Number(rep.status)],transaction:receipt.hash});
      }finally{provider.destroy();}
    }
    if(path==='/api/prove'){
      const {document,evidenceId}=input;
      if(!document||!evidenceId)throw Error('Provide document and evidenceId.');
      const parsed=JSON.parse(document);
      const leavesList=(parsed.evidenceLeaves||[]).map(l=>l.leaf);
      const idx=(parsed.evidenceLeaves||[]).findIndex(l=>l.id===evidenceId);
      if(idx<0)throw Error(`Evidence ID ${evidenceId} not found in report.`);
      const merkleProof=proof(leavesList,idx);
      return json(res,200,{
        evidenceId,
        leaf:parsed.evidenceLeaves[idx].leaf,
        proof:merkleProof,
        evidenceRoot:parsed.evidenceRoot
      });
    }
    if(path==='/api/verify-proof'){
      const {leaf:targetLeaf,proof:merkleProof,evidenceRoot}=input;
      if(!targetLeaf||!Array.isArray(merkleProof)||!evidenceRoot)throw Error('Provide leaf, proof, and evidenceRoot.');
      const cleanRoot=evidenceRoot.startsWith('0x')?evidenceRoot.slice(2):evidenceRoot;
      const valid=verifyProof(targetLeaf,merkleProof,cleanRoot);
      return json(res,200,{verified:valid});
    }
    if(path==='/api/history'){
      try{
        const {Contract,provider,config}=await registry();
        try{
          const contract=new Contract(config.address,config.abi,provider);
          const currentBlock=await provider.getBlockNumber();
          const fromBlock=Math.max(0,currentBlock-1000);
          const regEvents=await contract.queryFilter(contract.filters.Registered(),fromBlock);
          const revEvents=await contract.queryFilter(contract.filters.Revised(),fromBlock);
          const valEvents=await contract.queryFilter(contract.filters.Validated(),fromBlock);
          const dispEvents=await contract.queryFilter(contract.filters.Disputed(),fromBlock);
          return json(res,200,{
            registered:regEvents.map(e=>({commitment:e.args[0],reporter:e.args[1],blockNumber:e.blockNumber})),
            revised:revEvents.map(e=>({oldCommitment:e.args[0],newCommitment:e.args[1],blockNumber:e.blockNumber})),
            validated:valEvents.map(e=>({commitment:e.args[0],validator:e.args[1],count:Number(e.args[2]),blockNumber:e.blockNumber})),
            disputed:dispEvents.map(e=>({commitment:e.args[0],disputer:e.args[1],count:Number(e.args[3]),blockNumber:e.blockNumber}))
          });
        }finally{provider.destroy();}
      }catch{
        return json(res,200,{
          registered:[],revised:[],validated:[],disputed:[],
          notice:'Blockchain node offline or contract not deployed. Start local Ganache node or connect testnet.'
        });
      }
    }
    return json(res,404,{error:'Not found'});
  }catch(error){if(!res.headersSent)json(res,400,{error:String(error.message)});}
});
server.requestTimeout=30000;
server.on('error',error=>{
  console.error(error.code==='EADDRINUSE'
    ? `Port ${port} is busy. Set SCAMTHREADS_PORT to a free port and retry.`
    : error.message);
  process.exitCode=1;
});
if(!isVercel && process.env.NODE_ENV !== 'test'){
  server.listen(port,'127.0.0.1',()=>console.log(`HackMatrix: http://127.0.0.1:${port}`));
}

export default function handler(req, res) {
  server.emit('request', req, res);
}
