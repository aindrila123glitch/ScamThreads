import {createHash} from 'node:crypto';
import {Resolver} from 'node:dns/promises';

export const sha256=value=>createHash('sha256').update(value).digest('hex');
const within=(host,domain)=>host===domain||host.endsWith('.'+domain);
export function inspectForms(html,url){
  const signals=[];
  const base=/<base\b[^>]*\bhref\s*=\s*["']([^"']+)["']/i.exec(html)?.[1];
  for(const match of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)){
    const fields=[...match[2].matchAll(/<input\b[^>]*>/gi)];
    if(!fields.some(([tag])=>/\btype\s*=\s*["']?password\b|\b(?:name|id|autocomplete)\s*=\s*["']?(?:otp|one-time-code|verification[_-]?code)\b/i.test(tag)))continue;
    const attribute=/\saction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(' '+match[1]);
    try{
      const destination=new URL((attribute?.[1]??attribute?.[2]??attribute?.[3]??'').replaceAll('&amp;','&'),base?new URL(base,url):url);
      if(/^https?:$/.test(destination.protocol)&&destination.hostname!==url.hostname)
        signals.push('Password or OTP form targets a different hostname: '+destination.hostname);
    }catch{}
  }
  return [...new Set(signals)];
}
export function fingerprints(html,icon){
  const shape=[...html.matchAll(/<(form|input|button|select|textarea|iframe|img|h[1-3])\b/gi)]
    .slice(0,400).map(match=>match[1].toLowerCase());
  return {structure:shape.length>=8?sha256(shape.join('/')):null, favicon:icon?sha256(icon):null};
}
export function brandMatches(host,observed,brands){
  return brands.flatMap(brand=>{
    if(!Array.isArray(brand.domains)||brand.domains.some(domain=>within(host,domain)))return [];
    return ['favicon','structure'].filter(key=>observed[key]&&brand[key]?.includes(observed[key]))
      .map(key=>({finding:'Known '+brand.name+' '+key+' on an unapproved domain',source:'Configured brand fingerprints'}));
  });
}
export function variants(domain){
  domain=domain.toLowerCase().trim();
  if(!/^[a-z0-9-]{2,40}\.[a-z]{2,15}$/.test(domain))throw Error('Enter a two-label domain such as example.com.');
  const [name,tld]=domain.split('.');
  const candidates=new Set();
  for(let i=0;i<name.length;i++){
    candidates.add(name.slice(0,i)+name.slice(i+1)+'.'+tld);
    if(i+1<name.length)candidates.add(name.slice(0,i)+name[i+1]+name[i]+name.slice(i+2)+'.'+tld);
  }
  for(const [a,b] of Object.entries({o:'0',l:'1',i:'ı',a:'а',e:'е',c:'с',p:'р'}))
    if(name.includes(a))candidates.add(name.replace(a,b)+'.'+tld);
  candidates.add(name+'-login.'+tld);
  return [...new Set([...candidates].map(value=>new URL('https://'+value).hostname))].filter(value=>value!==domain).slice(0,10);
}
async function getJSON(url){
  const response=await fetch(url,{signal:AbortSignal.timeout(5500)});
  if(!response.ok)throw Error('HTTP '+response.status);
  return response.json();
}
export async function registration(host){
  try{
    const data=await getJSON('https://rdap.org/domain/'+encodeURIComponent(host));
    const created=data.events?.find(event=>event.eventAction==='registration')?.eventDate;
    const days=created?Math.floor((Date.now()-Date.parse(created))/86400000):null;
    const registrar=data.entities?.find(item=>item.roles?.includes('registrar'))?.vcardArray?.[1]
      ?.find(item=>item[0]==='fn')?.[3];
    return {created,days:Number.isFinite(days)&&days>=0?days:null,registrar,
      nameservers:(data.nameservers??[]).map(item=>item.ldhName?.toLowerCase()).filter(Boolean),status:'RDAP record found'};
  }catch(error){return {status:'RDAP unavailable: '+error.message};}
}
export async function watch(domain){
  const candidates=variants(domain);
  const checks=async host=>{
    const [rdap,ct]=await Promise.all([registration(host),(async()=>{
      try{
        const rows=await getJSON('https://crt.sh/?output=json&q='+encodeURIComponent(host));
        return {status:'Lookup completed',certificates:rows.filter(row=>row.name_value?.split('\n').includes(host)).slice(0,5)
          .map(row=>({id:row.id,issuer:row.issuer_name,issued:row.not_before}))};
      }catch(error){return {status:'CT unavailable: '+error.message,certificates:[]};}
    })()]);
    return {host,rdap,ct};
  };
  const results=[];
  for(let i=0;i<candidates.length;i+=3)results.push(...await Promise.all(candidates.slice(i,i+3).map(checks)));
  return results;
}
export async function infrastructure(host,ip){
  if(!ip)return {};
  const rdap=await registration(host);
  const resolver=new Resolver({timeout:1500,tries:1});
  const asn=await resolver.resolveTxt(ip.split('.').reverse().join('.')+'.origin.asn.cymru.com')
    .then(rows=>rows[0]?.join('').split('|')[0].trim()).catch(()=>null);
  return {ip,asn,...rdap};
}
export function validateExplanation(value, ids){
  return String(value).split(/\r?\n/).map(line=>line.trim()).filter(line=>{
    const match=/^([^.!?\[\]]+[.!?]?)\s+\[((?:E\d+)(?:,\s*E\d+)*)\]$/.exec(line);
    return match&&match[2].split(/,\s*/).every(id=>ids.has(id));
  }).join('\n');
}

