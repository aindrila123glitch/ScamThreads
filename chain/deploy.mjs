import {readFile,writeFile} from 'node:fs/promises';
import solc from 'solc';
import {JsonRpcProvider,Wallet,ContractFactory} from 'ethers';

const source=await readFile(new URL('./Registry.sol',import.meta.url),'utf8');
const build=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Registry.sol':{content:source}},
  settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
const artifact=build.contracts?.['Registry.sol']?.Registry;
if(!artifact) throw Error(JSON.stringify(build.errors));

const rpc=process.env.RPC_URL || 'http://127.0.0.1:8545';
const provider=new JsonRpcProvider(rpc);
const signer = process.env.PRIVATE_KEY ? new Wallet(process.env.PRIVATE_KEY, provider) : await provider.getSigner();
const contract=await new ContractFactory(artifact.abi,artifact.evm.bytecode.object,signer).deploy();
await contract.waitForDeployment();
const config={rpc,address:await contract.getAddress(),abi:artifact.abi,chainId:(await provider.getNetwork()).chainId.toString(),
  deployment:contract.deploymentTransaction().hash};
await writeFile(new URL('./deployment.json',import.meta.url),JSON.stringify(config,null,2));
console.log(config);
provider.destroy();
