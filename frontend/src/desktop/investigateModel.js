import {packetProtocol,packetTime,packetRisk,orderedEvidence} from './monitorModel.js';

export function investigationView(item,model={},context={}) {
 const cards=model.analystCards||[];
 const card=name=>cards.find(entry=>entry.label===name)||{};
 const reasons=model.riskExplanation?.groups||[];
 const findings=reasons.filter(group=>group.title!=='Confidence').flatMap(group=>(group.items||[]).map(entry=>entry.title)).filter(Boolean);
 const protocol=packetProtocol(item||{});
 const process=item?.process_name||((item?.pid&&card('Process Attribution').value)||'N/A');
 const service=card('Destination Service');
 const evidence=context.timeline||context.stream_context?.timeline||[];
 const timeline=evidence.map(entry=>({time:entry.timestamp||entry.ts,title:entry.summary||entry.label||entry.event||entry.type})).filter(entry=>entry.title);
 if(!timeline.length&&item)timeline.push({time:item.ts||item.timestamp,title:item.attack_type||`${protocol} packet (selected)`});
 const measuredRisk=packetRisk(item);
 return {protocol,protocolHint:card('Protocol Guess').value&&card('Protocol Guess').value!==protocol?`Analysis hint: ${card('Protocol Guess').value}`:'',process,service:service.value||'Not attributed',serviceHint:service.hint||'',risk:String(measuredRisk).replace(/^./,c=>c.toUpperCase()),analysisRisk:card('Risk').value||'',findings,
  why:card('Why It Matters').value||model.riskExplanation?.narrative||model.summaryText||'No assessment available for this evidence.',
  timeline:timeline.slice(0,10),entities:[...new Set([item?.src,item?.dst].filter(Boolean))]};
}

export function evidenceRows(items,search='',protocol='') {
 const term=search.trim().toLowerCase();
 return orderedEvidence(items).filter(({item})=>(!protocol||packetProtocol(item)===protocol)&&(!term||[item.src,item.dst,item.summary,item.detail,item.attack_type,item.process_name,item.id,packetProtocol(item),packetTime(item.ts??item.timestamp)].join(' ').toLowerCase().includes(term)));
}
