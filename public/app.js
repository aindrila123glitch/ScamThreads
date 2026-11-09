const el=id=>document.getElementById(id);
let last;
async function api(path,data){
  const response=await fetch('/api/'+path,data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok)throw Error(result.error);
  return result;
}
function line(label,value){
  const p=document.createElement('p');
  const strong=document.createElement('strong');
  strong.textContent=label+' · ';
  p.append(strong,String(value));
  el('result').append(p);
}
function run(button,target,fn){
  button.disabled=true;
  return Promise.resolve().then(fn).catch(error=>{el(target).textContent=error.message;}).finally(()=>{button.disabled=false;});
}
el('scan').onsubmit=event=>{
  event.preventDefault();
  last=null;
  el('report').disabled=true;
  el('result').replaceChildren();
  el('status').textContent='Investigating…';
  run(event.submitter,'status',async()=>{
    last=await api('scan',{url:el('url').value,message:el('message').value,deep:true});
    el('status').textContent=last.verdict+(last.demo?' · Demo fixture':'');

    const rcView=el('redirect-chain-view');
    if(rcView){
      rcView.replaceChildren();
      if(last.redirects&&last.redirects.length>0){
        const rcBox=document.createElement('div');
        rcBox.style.cssText='background:#131d2a; border:1px solid #233549; border-radius:6px; padding:0.75rem; margin-bottom:1rem;';
        const rcHeading=document.createElement('strong');
        rcHeading.textContent=`Redirect Chain Analysis (${last.redirects.length} hop(s))`;
        rcBox.append(rcHeading);
        const ul=document.createElement('ul');
        ul.style.cssText='list-style:none; padding:0; margin:0.5rem 0; font-family:monospace; font-size:0.85rem;';
        const allHops=[last.initial,...last.redirects];
        for(let i=0;i<allHops.length;i++){
          const li=document.createElement('li');
          li.style.cssText='padding:0.35rem 0; border-bottom:1px dashed #233549;';
          const prefix=i===0?'🟢 Origin: ':i===allHops.length-1?'🎯 Final: ':`↳ Hop ${i}: `;
          const hopSpan=document.createElement('span');
          hopSpan.textContent=prefix+allHops[i];
          li.append(hopSpan);
          if(i>0){
            try{
              const prevHost=new URL(allHops[i-1]).hostname;
              const curHost=new URL(allHops[i]).hostname;
              if(prevHost!==curHost){
                const badge=document.createElement('span');
                badge.textContent=' [CROSS-DOMAIN JUMP]';
                badge.style.cssText='color:#f27474; font-weight:bold;';
                li.append(badge);
              }
            }catch{}
          }
          ul.append(li);
        }
        rcBox.append(ul);
        rcView.append(rcBox);
      }
    }

    if(last.coverage){
      const covDiv=document.createElement('div');
      covDiv.className='coverage-meter';
      covDiv.style.cssText='background:#131d2a; border:1px solid #233549; border-radius:6px; padding:0.75rem; margin-bottom:1rem;';
      const covHeading=document.createElement('strong');
      covHeading.textContent=`Evidence Coverage: ${last.coverage.done} of ${last.coverage.total} checks completed (${Math.round(last.coverage.done/last.coverage.total*100)}%)`;
      const bar=document.createElement('div');
      bar.style.cssText='height:8px; background:#233549; border-radius:4px; margin:0.5rem 0; overflow:hidden;';
      const fill=document.createElement('div');
      fill.style.cssText=`height:100%; width:${Math.round(last.coverage.done/last.coverage.total*100)}%; background:#69ebbd; transition:width 0.3s;`;
      bar.append(fill);
      covDiv.append(covHeading,bar);
      const skippedOrFailed=(last.checks||[]).filter(c=>c.status!=='done');
      if(skippedOrFailed.length){
        const skippedList=document.createElement('small');
        skippedList.style.cssText='color:#8192aa; display:block;';
        skippedList.textContent='Skipped or limited checks: '+skippedOrFailed.map(c=>c.name+(c.reason?` (${c.reason})`:'')).join(' · ');
        covDiv.append(skippedList);
      }
      el('result').append(covDiv);
    }
    line('Scan time',last.time);
    line('Destination',last.destination??'Unavailable');
    line('TLS',last.tls);
    for(const hop of last.redirects)line('Redirect',hop);
    for(const [lane,label] of [['technical','Technical evidence'],['language','Suspicious language and input checks']]){
      const heading=document.createElement('h3');
      heading.textContent=label;
      el('result').append(heading);
      const items=last.evidence.filter(item=>(item.lane??'technical')===lane);
      if(!items.length)line('Coverage','No findings in this lane.');
      for(const evidence of items)line('['+evidence.id+'] '+evidence.source,evidence.finding);
    }
    for(const [key,value] of Object.entries(last.observed??{}))if(value)line(key+' SHA-256',value);
    if(last.network?.ip)line('Infrastructure',JSON.stringify(last.network));
    for(const check of last.tlsChecks){
      line('TLS at '+check.url,check.status);
      for(const cert of check.certificates)line(cert.subject??'Certificate',cert.fingerprint+' · '+cert.expires);
    }
    for(const finding of last.security)line(finding.issue+' · '+finding.severity,finding.evidence+'. '+finding.fix);
    for(const limit of last.limits)line('Coverage limitation',limit);
    line('Recommended action',last.action);
    if(last.explanation)line((last.explanationSource||'AI')+' explanation',last.explanation);

    const guide=el('incident-guide');
    if(guide){
      guide.replaceChildren();
      if(['High Risk','Confirmed Malicious'].includes(last.verdict)){
        guide.style.display='block';
        guide.style.cssText='background:#2d1414; border:1px solid #7c2d2d; border-radius:6px; padding:0.85rem; margin-top:1rem;';
        const h3=document.createElement('h3');
        h3.textContent='🚨 Emergency Checklist: If You Already Clicked This Link';
        h3.style.color='#ff8080';
        guide.append(h3);
        const steps=[
          '1. Disconnect & Freeze: Contact your bank immediately. Request urgent freezing of debit/credit cards, UPI IDs, and net banking access.',
          '2. Report Incident: File an official complaint on the National Cyber Crime Reporting Portal (https://cybercrime.gov.in) or call National Cybercrime Helpline 1930.',
          '3. Reset Credentials: Change account passwords immediately from a separate, secure device. Terminate all active login sessions.',
          '4. Remove Remote Software: If prompted to install AnyDesk, TeamViewer, or RustDesk, uninstall them immediately and disconnect from Wi-Fi.',
          '5. Preserve Evidence: Do not delete SMS alerts, WhatsApp chats, UPI transaction IDs (UTR), or call history. Save them for the police cyber cell.'
        ];
        const ol=document.createElement('ol');
        ol.style.cssText='margin:0.5rem 0 0 1.2rem; padding:0; font-size:0.85rem; color:#f0d0d0; line-height:1.5;';
        for(const step of steps){
          const li=document.createElement('li');
          li.textContent=step;
          ol.append(li);
        }
        guide.append(ol);
      } else {
        guide.style.display='none';
      }
    }
    el('report').disabled=false;
  });
};
el('report').onclick=()=>{if(last)run(el('report'),'chain',async()=>{
  const result=await api('report',{report:last});
  el('document').value=result.document;
  el('chain').textContent=result.commitment;
  await campaigns();
});};
for(const action of ['register','verify'])el(action).onclick=()=>run(el(action),'chain',async()=>{
  const result=await api(action,{document:el('document').value});
  el('chain').textContent=JSON.stringify(result,null,2);
  renderChainStatus(result);
});
el('validate-btn').onclick=()=>run(el('validate-btn'),'chain',async()=>{
  const result=await api('validate',{document:el('document').value});
  el('chain').textContent=JSON.stringify(result,null,2);
  renderChainStatus(result);
});
el('dispute-btn').onclick=()=>run(el('dispute-btn'),'chain',async()=>{
  const result=await api('dispute',{document:el('document').value,reason:'Disputed by community validator'});
  el('chain').textContent=JSON.stringify(result,null,2);
  renderChainStatus(result);
});
el('prove-btn').onclick=()=>run(el('prove-btn'),'chain',async()=>{
  const evidenceId=el('evidence-id-input').value.trim();
  if(!evidenceId)throw Error('Enter an Evidence ID like E1');
  const proofResult=await api('prove',{document:el('document').value,evidenceId});
  const verification=await api('verify-proof',proofResult);
  el('chain').textContent=JSON.stringify({...proofResult,proofValid:verification.verified},null,2);
});
function renderChainStatus(data){
  const tl=el('chain-timeline');
  if(!tl)return;
  tl.replaceChildren();
  const box=document.createElement('div');
  box.style.cssText='padding:0.5rem; background:#182535; border-radius:4px; font-size:0.85rem;';
  const status=data.report?.status||data.status||(data.verified?'Submitted':'Unregistered');
  const p=document.createElement('p');
  p.textContent=`Status: ${status} · Validations: ${data.report?.validations??data.validations??0} · Disputes: ${data.report?.disputes??data.disputes??0}`;
  box.append(p);
  tl.append(box);
}
el('download').onclick=()=>{
  const url=URL.createObjectURL(new Blob([el('document').value],{type:'application/json'}));
  const a=document.createElement('a');
  a.href=url;a.download='hackmatrix-report.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};
async function campaigns(){
  const list=await api('campaigns');
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  const recent=list.slice(-24);
  svg.setAttribute('viewBox','0 0 560 280');
  svg.setAttribute('width','100%');
  svg.setAttribute('role','img');
  svg.setAttribute('aria-label','Campaign evidence graph. See link details below.');
  const nodes=new Map(recent.map((entry,index)=>{
    const angle=index*2*Math.PI/recent.length;
    return [entry.id,[280+225*Math.cos(angle),140+100*Math.sin(angle)]];
  }));
  function add(name,attributes){
    const item=document.createElementNS(svg.namespaceURI,name);
    for(const [key,value] of Object.entries(attributes))item.setAttribute(key,value);
    svg.append(item);
    return item;
  }
  for(const entry of recent){
    const [x1,y1]=nodes.get(entry.id);
    for(const link of entry.links){
      const target=nodes.get(link.report);
      if(!target)continue;
      const weak=link.matches.every(match=>match.includes('(weak)'));
      const edge=add('line',{x1,y1,x2:target[0],y2:target[1],stroke:weak?'#8192aa':'#69ebbd','stroke-dasharray':weak?'5 4':'none'});
      const title=document.createElementNS(svg.namespaceURI,'title');
      title.textContent=link.matches.join(', ');
      edge.append(title);
    }
  }
  for(const [id,[cx,cy]] of nodes){
    add('circle',{cx,cy,r:9,fill:'#69ebbd'});
    add('text',{x:cx,y:cy+23,'text-anchor':'middle',fill:'#e6eefb','font-size':11}).textContent=id.slice(0,8);
  }
  el('graph').replaceChildren(...(recent.length?[svg]:[]));
  el('campaign').textContent=list.length?list.map(entry=>entry.id+' · '+entry.verdict+
    entry.links.map(link=>'\n  ↳ '+link.report+' · '+link.matches.join(', ')).join('')).join('\n\n'):'No reports yet.';
}
el('refresh').onclick=()=>run(el('refresh'),'campaign',campaigns);
el('fixtures').onchange=()=>{if(el('fixtures').value)el('url').value=el('fixtures').value;};
api('fixtures').then(cases=>cases.forEach(url=>el('fixtures').add(new Option(url,url)))).catch(error=>{el('status').textContent=error.message;});
if(window.location.hash.startsWith('#url=')){
  const deepUrl=decodeURIComponent(window.location.hash.slice(5));
  if(deepUrl)el('url').value=deepUrl;
}
campaigns().catch(error=>{el('campaign').textContent=error.message;});
let watchTimer;
el('watch').onsubmit=event=>{
  event.preventDefault();
  clearInterval(watchTimer);
  const domain=el('brand').value;
  const check=()=>run(event.submitter,'watch-result',async()=>{
    el('watch-result').textContent='Checking DNS registration records and certificate logs…';
    const results=await api('watch',{domain});
    el('watch-result').textContent=results.map(({host,rdap,ct})=>
      host+' · '+rdap.status+(rdap.days!=null?' · '+rdap.days+' days old':'')+
      '\n  CT: '+ct.status+' · '+ct.certificates.length+' exact-name result(s)'+
      ct.certificates.map(cert=>'\n  #'+cert.id+' · '+cert.issued+' · '+cert.issuer).join('')).join('\n\n');
  });
  check();
  if(el('repeat').checked)watchTimer=setInterval(check,15*60*1000);
};
el('repeat').onchange=()=>{if(!el('repeat').checked)clearInterval(watchTimer);};

function renderFileResult(data){
  const container=el('file-result');
  container.replaceChildren();
  const addP=(label,val)=>{
    const p=document.createElement('p');
    const strong=document.createElement('strong');
    strong.textContent=label+' · ';
    p.append(strong,String(val));
    container.append(p);
  };
  const h3=document.createElement('h3');
  h3.textContent=data.verdict+(data.label?' · '+data.label:'');
  container.append(h3);
  addP('Filename',data.name||'unnamed');
  addP('SHA-256',data.sha256);
  addP('Size',(data.size??0)+' bytes');
  addP('Entropy',data.entropy+' / 8.0');
  if(Array.isArray(data.evidence)&&data.evidence.length){
    for(const ev of data.evidence)addP(`[${ev.id}] ${ev.source}`,ev.finding);
  }
  if(Array.isArray(data.limits)&&data.limits.length){
    for(const lim of data.limits)addP('Limitation',lim);
  }
  if(data.action)addP('Action',data.action);
}

el('file-form').onsubmit=event=>{
  event.preventDefault();
  const file=el('file-input').files?.[0];
  if(!file)return;
  run(event.submitter,'file-result',async()=>{
    el('file-result').textContent='Analyzing file payload…';
    const response=await fetch('/api/file',{
      method:'POST',
      headers:{'Content-Type':'application/octet-stream','X-Filename':encodeURIComponent(file.name)},
      body:file
    });
    const result=await response.json();
    if(!response.ok)throw Error(result.error);
    renderFileResult(result);
  });
};

el('download-form').onsubmit=event=>{
  event.preventDefault();
  const url=el('download-url').value;
  if(!url)return;
  run(event.submitter,'file-result',async()=>{
    el('file-result').textContent='Fetching and inspecting file…';
    const result=await api('download',{url});
    renderFileResult(result);
  });
};

if(el('qr-input')){
  el('qr-input').onchange=event=>{
    const file=event.target.files?.[0];
    if(!file)return;
    const qrStatus=el('qr-status');
    qrStatus.textContent='Decoding QR image in browser memory…';
    const reader=new FileReader();
    reader.onload=e=>{
      const img=new Image();
      img.onload=()=>{
        const canvas=document.createElement('canvas');
        canvas.width=img.width;
        canvas.height=img.height;
        const ctx=canvas.getContext('2d');
        ctx.drawImage(img,0,0);
        const imgData=ctx.getImageData(0,0,img.width,img.height);
        if(typeof jsQR!=='undefined'){
          const code=jsQR(imgData.data,img.width,img.height);
          if(code&&code.data){
            qrStatus.textContent='QR Code decoded successfully!';
            qrStatus.style.color='#69ebbd';
            if(code.data.startsWith('upi://')){
              el('message').value='Decoded UPI QR String: '+code.data;
              const alertBox=document.createElement('div');
              alertBox.style.cssText='padding:0.5rem; background:#3b1d1d; border:1px solid #7c2d2d; border-radius:4px; margin-top:0.5rem; color:#ffb0b0; font-size:0.85rem; font-weight:bold;';
              alertBox.textContent='⚠️ CRITICAL WARNING: Scanning a QR code or entering your UPI PIN always DEDUCTS money from your bank account. Receiving money or refunds NEVER requires entering your PIN.';
              qrStatus.append(alertBox);
            }else if(/^https?:\/\//i.test(code.data)){
              el('url').value=code.data;
            }else{
              el('message').value=code.data;
            }
          }else{
            qrStatus.textContent='No QR code could be resolved from this image.';
            qrStatus.style.color='#f27474';
          }
        }else{
          qrStatus.textContent='QR decoder library unavailable.';
        }
      };
      img.src=e.target.result;
    };
    reader.readAsDataURL(file);
  };
}

async function loadEvalMetrics(){
  const container=el('eval-metrics');
  if(!container)return;
  try{
    const data=await api('eval');
    if(data.status){
      container.textContent=data.status;
      return;
    }
    container.replaceChildren();
    const box=document.createElement('div');
    box.style.cssText='background:#131d2a; border:1px solid #233549; border-radius:6px; padding:0.75rem;';
    const h4=document.createElement('strong');
    h4.textContent=`Offline Accuracy Benchmark: ${data.metrics?.accuracy}% (F1-Score: ${data.metrics?.f1Score}%)`;
    box.append(h4);
    const stats=document.createElement('p');
    stats.style.cssText='font-size:0.85rem; margin:0.35rem 0; color:#d6e2f1;';
    stats.textContent=`Evaluated: ${data.evaluatedAt} · Total Samples: ${data.dataset?.totalSamples} (${data.dataset?.benignSamples} benign, ${data.dataset?.phishingSamples} phishing)`;
    box.append(stats);
    const matrix=document.createElement('div');
    matrix.style.cssText='display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; margin-top:0.5rem; font-size:0.8rem;';
    const tpCard=document.createElement('div');
    tpCard.style.cssText='background:#182535; padding:0.4rem; border-radius:4px;';
    tpCard.textContent=`True Positives (Phishing Flagged): ${data.confusionMatrix?.truePositives}`;
    const tnCard=document.createElement('div');
    tnCard.style.cssText='background:#182535; padding:0.4rem; border-radius:4px;';
    tnCard.textContent=`True Negatives (Benign Cleared): ${data.confusionMatrix?.trueNegatives}`;
    const fpCard=document.createElement('div');
    fpCard.style.cssText='background:#182535; padding:0.4rem; border-radius:4px;';
    fpCard.textContent=`False Positives: ${data.confusionMatrix?.falsePositives}`;
    const fnCard=document.createElement('div');
    fnCard.style.cssText='background:#182535; padding:0.4rem; border-radius:4px;';
    fnCard.textContent=`False Negatives: ${data.confusionMatrix?.falseNegatives}`;
    matrix.append(tpCard,tnCard,fpCard,fnCard);
    box.append(matrix);
    container.append(box);
  }catch(err){
    container.textContent='Benchmark unavailable: '+err.message;
  }
}

if(el('eval-refresh-btn')){
  el('eval-refresh-btn').onclick=()=>run(el('eval-refresh-btn'),'eval-metrics',loadEvalMetrics);
  loadEvalMetrics();
}
