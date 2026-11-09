export function packetTime(value, milliseconds=true) {
 if(value===null||value===undefined||value==='')return '-';
 if(typeof value==='string'&&/^\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/.test(value)) {
  const [hour,minute,second]=value.split(':').map(Number);
  return hour<24&&minute<60&&second<60?value:'-';
 }
 if(typeof value==='string'&&/^\d+(?:\.\d+)?$/.test(value))value=Number(value);
 const date=new Date(typeof value==='number'&&value<1e12?value*1000:value);
 if(!Number.isFinite(date.getTime()))return '-';
 const time=date.toLocaleTimeString('en-GB',{hour12:false});
 return milliseconds?`${time}.${String(date.getMilliseconds()).padStart(3,'0')}`:time;
}

export function packetRisk(packet={}) {
 packet=packet||{};
 const value=String(packet.risk_level||packet.severity||'').toLowerCase();
 if(value==='critical'||value==='malicious')return 'critical';
 if(value==='high')return 'high';
 if(value==='medium'||value==='warning'||value==='suspicious')return 'medium';
 return packet.is_alert?'high':'low';
}

export function packetProtocol(packet={}) {
 const app=String(packet.app_protocol||'').trim();
 return app&&!['UNKNOWN','OTHER','UNCLASSIFIED'].includes(app.toUpperCase())?app:packet.proto||packet.protocol||app||'-';
}

export function packetInfo(packet={}) {
 return packet.info||packet.summary||packet.detail||packet.app_protocol_metadata?.summary||'-';
}

export function destinationDomain(packet={}) {
 const domain=String(packet.destination_domain||packet.service_attribution?.destination_domain||'').trim();
 const source=String(packet.destination_domain_source||packet.service_attribution?.destination_domain_source||'').trim();
 const candidates=packet.destination_domain_candidates||packet.service_attribution?.destination_domain_candidates||[];
 return {domain:domain||(source==='DNS answer (ambiguous)'?'Multiple possible domains':'-'),source,candidates:Array.isArray(candidates)?candidates:[]};
}

export function flowRows(packet={}) {
 return [
  ['Direction',packet.direction||packet.traffic_direction],
  ['Source Port',packet.sport??packet.src_port],
  ['Destination Port',packet.dport??packet.dst_port],
  ['Flags',packet.flags??packet.tcp_flags],
  ['Sequence Number',packet.seq??packet.tcp_seq],
  ['Acknowledgment Number',packet.ack??packet.tcp_ack],
  ['Window Size',packet.window??packet.tcp_window],
  ['TTL / Hop Limit',packet.ttl??packet.hop_limit],
  ['MSS',packet.mss??packet.tcp_mss],
  ['Flow',packet.flow_id||packet.conversation_id],
 ].filter(([,value])=>value!==undefined&&value!==null&&value!=='');
}

export function orderedEvidence(items=[]) {
 const stamp=item=>{
  let value=item.ts??item.timestamp;
  if(typeof value==='string'&&/^\d+(?:\.\d+)?$/.test(value))value=Number(value);
  if(typeof value==='number')return value<1e12?value*1000:value;
  const parsed=Date.parse(value);
  return Number.isFinite(parsed)?parsed:-Infinity;
 };
 return items.map((item,index)=>({item,index})).sort((a,b)=>stamp(b.item)-stamp(a.item)||a.index-b.index);
}

export function evidenceDate(value) {
 if(value===null||value===undefined||value==='')return '-';
 const date=new Date(typeof value==='number'&&value<1e12?value*1000:value);
 return Number.isFinite(date.getTime())?`${date.toLocaleDateString('en-GB')} ${packetTime(value)}`:String(value);
}

export function capturedDissection(packet) {
 const fields=rows=>rows.filter(([,value])=>value!==null&&value!==undefined&&value!=='').map(([label,value])=>({label,value}));
 const layers=[{name:'Frame',fields:fields([['Timestamp',packet.ts??packet.timestamp],['Frame Length',packet.length],['Direction',packet.direction]])}];
 if(packet.src_mac||packet.dst_mac)layers.push({name:'Ethernet',fields:fields([['Source MAC',packet.src_mac],['Destination MAC',packet.dst_mac]])});
 if(packet.src||packet.dst)layers.push({name:'Network',fields:fields([['Source',packet.src],['Destination',packet.dst],['TTL / Hop Limit',packet.ttl??packet.hop_limit],['Protocol',packet.proto]])});
 const transport=flowRows(packet).filter(([name])=>!['Direction','TTL / Hop Limit','Flow'].includes(name));
 if(transport.length)layers.push({name:packet.proto||'Transport',fields:fields(transport)});
 return {layers,metadata_fallback:true,hex:{rows:[],warning:'Captured metadata only; full dissection is no longer available.'}};
}
