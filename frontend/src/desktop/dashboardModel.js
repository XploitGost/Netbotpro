export function formatTrafficRate(value) {
 const numeric=Number(value),rate=Number.isFinite(numeric)?Math.max(0,numeric):0;
 return rate>=1e6?`${(rate/1e6).toFixed(1)} Mb/s`:rate>=1000?`${(rate/1000).toFixed(1)} Kb/s`:`${Math.round(rate)} b/s`;
}

export function mergeHealthMetrics(...sources) {
 const result={};
 for(const source of sources)for(const [key,value] of Object.entries(source||{})) {
  if(value===null||value===undefined)continue;
  if(typeof value==='object'&&!Array.isArray(value))result[key]={...(result[key]||{}),...value};
  else result[key]=value;
 }
 return result;
}

export function metricChange(current,previous,{percentage=false,increaseBad=false}={}) {
 if(current===null||current===undefined||previous===null||previous===undefined)return null;
 const value=Number(current),before=Number(previous);
 if(!Number.isFinite(value)||!Number.isFinite(before))return null;
 const difference=value-before;
 const amount=percentage&&before>0?Math.round(100*difference/before):percentage?Math.round(difference):difference;
 const suffix=percentage?(before>0?'%':'/s'):'';
 const sign=amount>0?'+':'';
 return {text:`${sign}${amount}${suffix}`,direction:amount>0?'up':amount<0?'down':'flat',
  tone:amount===0?'neutral':(amount>0)===increaseBad?'bad':'good'};
}

export function endpointActivity(history,ip) {
 const values=history.slice(-6);
 const intervals=values.slice(1).map((sample,index)=>{
  const previous=values[index].counts[ip],current=sample.counts[ip];
  return previous===undefined||current===undefined||current<previous?null:current-previous;
 });
 return [...Array(Math.max(0,5-intervals.length)).fill(null),...intervals];
}

export function endpointRiskSnapshot(summary) {
 const source=summary?.endpoint_risk;
 if(!source||source.scope!=='detector_events'||!Array.isArray(source.items))return {available:false,items:[]};
 const ranks={info:0,low:1,medium:2,high:3,critical:4};
 const items=source.items.filter(row=>row.ip&&Number.isFinite(Number(row.count))&&Number(row.count)>0&&row.risk in ranks).map(row=>({...row,count:Number(row.count),trend:Array.from({length:5},(_,index)=>{const value=row.trend?.[index];return value!==null&&value!==undefined&&Number.isFinite(Number(value))&&Number(value)>=0?Number(value):null;})})).sort((a,b)=>ranks[b.risk]-ranks[a.risk]||b.count-a.count||a.ip.localeCompare(b.ip)).slice(0,8);
 return {...source,available:true,items};
}

export function resolveCaptureInterface(items, selected) {
 if(!selected)return null;
 const key=String(selected).trim().toLowerCase();
 return items.find(item=>['value','name','network_name','label'].some(field=>
  item[field]&&String(item[field]).trim().toLowerCase()===key))||null;
}

export function captureInterfaceLabel(item) {
 if(!item)return {name:'Interface unavailable',vpn:false};
 const name=item.name||item.label||item.value||'Interface unavailable';
 const text=`${item.name||''} ${item.description||''}`.toLowerCase();
 const kind=String(item.value||'').startsWith('ras:')?'PPP':
  /tap-windows|\btap[- ]/.test(text)?'TAP':
  /wireguard/.test(text)?'WireGuard':/wintun/.test(text)?'Wintun':
  /openvpn/.test(text)?'OpenVPN':/\bvpn\b|ivacy/.test(text)?'VPN':null;
 return {name:kind?`${name} - VPN${kind==='VPN'?'':` (${kind})`}`:name,vpn:!!kind};
}

export function activeConnectionDisplay(items, recommended, selected) {
 const routed=resolveCaptureInterface(items,recommended)||items.find(item=>item.recommended);
 const current=resolveCaptureInterface(items,selected);
 const active=routed&&routed.is_up!==false?routed:current&&current.is_up!==false?current:null;
 if(!active)return {name:'Connection unavailable',detail:'No active route detected'};
 const technical=captureInterfaceLabel(active);
 const name=active.connection_name||String(active.name||active.network_name||active.label||active.value||'Connection unavailable').replace(/^ras:/i,'').replace(/\s+VPN$/i,'');
 const detail=technical.vpn?technical.name:[active.name||name,active.description].filter(Boolean).join(' - ');
 return {name,detail:`Active: ${detail}`};
}

export function protocolDistribution(summary) {
 const rows=(summary?.top_protocols||[]).map(row=>({protocol:row.protocol,count:Number(row.count??row.flows??row.value??0)}))
  .filter(row=>row.protocol&&Number.isFinite(row.count)&&row.count>0);
 const known=rows.reduce((sum,row)=>sum+row.count,0);
 const supplied=Number(summary?.total_flows);
 const total=Math.max(known,Number.isFinite(supplied)?supplied:0);
 if(!total)return [];
 const named=rows.filter(row=>String(row.protocol).toLowerCase()!=='other');
 const first=named.slice(0,8);
 const needsOther=total>first.reduce((sum,row)=>sum+row.count,0);
 const visible=named.slice(0,needsOther?7:8);
 const remaining=total-visible.reduce((sum,row)=>sum+row.count,0);
 if(remaining>0)visible.push({protocol:'Other',count:remaining});
 return visible.map(row=>({...row,percentage:100*row.count/total}));
}
