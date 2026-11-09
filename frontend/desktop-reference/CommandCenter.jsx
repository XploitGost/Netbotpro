import React, {useEffect, useMemo, useRef, useState} from 'react';
import {queueSnapshot,pressureLabel} from './queueModel.js';
import {protocolDistribution,formatTrafficRate,metricChange,endpointRiskSnapshot,captureInterfaceLabel,resolveCaptureInterface,activeConnectionDisplay,mergeHealthMetrics} from './dashboardModel.js';
import {BUCKET_MS, recordPacket,resetTraffic,trafficPoints,trafficRates,hoverSample} from './trafficModel.js';
export {recordPacket,resetTraffic};
import {ArrowRight, ArrowDown, ArrowUp, ChevronDown, Menu, Check, CircleCheck, CircleAlert, ChartNoAxesColumnIncreasing, Shield, Monitor, Database, Star, Triangle, TriangleAlert, Activity, House, Search, Network, Server, ChartColumn, Settings, Route, FileSearch, Download, Play, Square, EthernetPort} from 'lucide-react';

const colors = {inbound:'#009fe9', outbound:'#00b6ad', suspicious:'#ff891c', malicious:'#ff3b3b'};
const label = value => String(value ?? '').replaceAll('_',' ').replaceAll(/\b\w/g, c=>c.toUpperCase());
const time = value => { const d=new Date(typeof value==='number' && value<1e12?value*1000:value); return Number.isFinite(d.getTime())?d.toLocaleTimeString('en-GB',{hour12:false}):'-'; };
const num = value => Number(value||0).toLocaleString('en-US');
function HealthValue(value) {return typeof value==='object' && value!==null?value.health||value.status||value.state||'unavailable':value||'unavailable';}
function ProcessingHealth(metrics) {
 const states=[HealthValue(metrics.packet_queue||metrics.pipeline)];
 if(metrics.flow_worker_pool?.enabled!==false&&metrics.flow_worker_pool)states.push(HealthValue(metrics.flow_worker_pool));
 const rank={critical:4,failed:4,error:4,degraded:3,warning:3,unavailable:2,unknown:2,idle:1,healthy:0,ok:0,ready:0};
 return states.map(value=>String(value).toLowerCase()).sort((a,b)=>(rank[b]??2)-(rank[a]??2))[0];
}
const addresses=(v,key)=>v[`${key}_hosts`]||v[`${key}_ips`]||v[key==='source'?'sources':'destinations']||[];
const explanation=v=>v.description||v.summary||(v.evidence||v.risk_reasons||[])[0]||'-';
function Severity({value='low'}) {const v=String(value).toLowerCase();return <span className={`ref-severity ${v}`}><Star size={11} fill="currentColor"/>{label(v)}</span>;}
function Panel({title, target, onNavigate, children, className=''}) {return <section className={`ref-panel ${className}`}><header><h2>{title}</h2>{target&&<button title={`Open ${title}`} aria-label={`Open ${title}`} onClick={()=>onNavigate(target)}><ArrowRight size={17}/></button>}</header>{children}</section>;}
function Empty({children}) {return <div className="ref-empty">{children}</div>;}

export function ReferenceIcon({name,size=20,className=''}) {
 const icons={command:House,home:House,monitor:Activity,inspect:Search,search:Search,flows:Network,incidents:TriangleAlert,agents:Server,fleet:Server,reports:ChartColumn,settings:Settings,traceroute:Route,offline:FileSearch,exports:Download,play:Play,start:Play,stop:Square,ethernet:EthernetPort,network:EthernetPort,arrowDown:ArrowDown,arrowUp:ArrowUp};
 const Icon=icons[name];return Icon?<Icon size={size} className={className} aria-hidden="true"/>:React.createElement(OriginalNetBotIcon,{name,size,className});
}

export function Topbar({api,fixtureMode,backendState,dashboardState,connectionLabel,connectionState,sniffer={},settings={},interfaces=[],isBusy,canStartSniffer,onStartSniffer,onStopSniffer,onOpenSettings,onToggleNav}) {
 const [network,setNetwork]=useState(null);
 useEffect(()=>{if(!api?.getInterfaces||fixtureMode)return;let active=true,busy=false;async function refresh(){if(busy)return;busy=true;try{const result=await api.getInterfaces();if(active)setNetwork(result);}catch{if(active)setNetwork(null);}finally{busy=false;}}refresh();const timer=setInterval(refresh,5000);return()=>{active=false;clearInterval(timer);};},[api,fixtureMode]);
 const [,tick]=useState(0);useEffect(()=>{const id=setInterval(()=>tick(n=>n+1),1000);return()=>clearInterval(id);},[]);
 const state={...sniffer,...(fixtureMode?{}:trafficRates())};const ready=backendState==='connected'&&dashboardState==='success';
 const elapsed=state.running&&Number(state.capture_started_at)>0?Date.now()/1000-Number(state.capture_started_at):Number(state.elapsed_seconds||0);
 const seconds=Math.max(0,Math.floor(elapsed));const clock=[Math.floor(seconds/3600),Math.floor(seconds%3600/60),seconds%60].map(n=>String(n).padStart(2,'0')).join(':');
 const available=network?.items||interfaces;
 const selected=state.iface||settings.iface;const iface=resolveCaptureInterface(available,selected);
 const current=captureInterfaceLabel(iface||{value:selected,name:selected});
 const connection=activeConnectionDisplay(available,network?.recommended,selected);
 const name=<span className="ref-adapter-name" title={`Capture adapter: ${current.name}. ${connection.detail}. Capture selection has not been changed.`}><span>{connection.name}</span><small>{connection.detail}</small></span>;
 const status=fixtureMode?'Fixture data':state.capture_error?'Capture error':ready&&state.running&&connectionLabel==='Connected'?label(state.capture_health||state.health||'connected'):connectionLabel||'Connecting';
 const warning=/degraded|warning|connecting|unavailable|offline/i.test(status);
 const rate=formatTrafficRate;
 return <header className="soc-topbar ref-topbar" aria-label="Capture status"><button className="icon-button soc-nav-toggle" aria-label="Open navigation" onClick={onToggleNav}><Menu size={18}/></button><div className="soc-topbar-section soc-live-state"><i className={`soc-live-dot ${ready&&state.running?'is-running':''}`}/><strong>{fixtureMode?'SIMULATED SESSION':!ready?'CAPTURE UNKNOWN':state.running?'LIVE CAPTURE':'CAPTURE IDLE'}</strong></div><button className="soc-topbar-section ref-adapter" title="Change capture adapter in Settings" onClick={onOpenSettings}><EthernetPort size={18}/><span>{name}</span><ChevronDown size={16}/></button><div className={`soc-status-pill ${state.capture_error?'ref-status-error':warning?'ref-status-pending':''}`}>{state.capture_error||warning?<CircleAlert size={15}/>:<CircleCheck size={15}/>} {status}</div><div className="soc-topbar-section soc-rate-state"><ArrowDown size={18} className="ref-incoming"/><span>{ready?rate(state.inbound_bps||state.rx_bps):'-'}</span></div><div className="soc-topbar-section soc-rate-state"><ArrowUp size={18} className="ref-outgoing"/><span>{ready?rate(state.outbound_bps||state.tx_bps):'-'}</span></div><div className="soc-topbar-section soc-counter-state"><span>Elapsed</span><strong>{ready?clock:'-'}</strong></div><div className="soc-topbar-actions"><button className="primary soc-start" disabled={isBusy||!canStartSniffer} onClick={onStartSniffer}><Play size={16} fill="currentColor"/>Start</button><button className="secondary soc-stop" disabled={isBusy||!ready||!state.running} onClick={onStopSniffer}><Square size={16} fill="currentColor"/>Stop</button><button className="secondary soc-settings" title="Settings" aria-label="Open Settings" onClick={onOpenSettings}><Settings size={20}/></button></div></header>;
}

export function Navigation({activePage,onNavigate,healthLabel='System Healthy',healthState='verified',version='v0.2.0',lastUpdated='',streamLabel='',open=false,onClose}) {
 const items=[['command','Command Center'],['monitor','Live Monitor'],['inspect','Investigate'],['flows','Flows'],['incidents','Incidents'],['agents','Fleet'],['reports','Reports'],['settings','Settings']];
 const extras=[['traceroute','Traceroute'],['offline','Offline Analysis'],['exports','Exports']];
 const navigate=id=>{onNavigate(id);onClose?.();};
 const button=([id,title])=><button key={id} type="button" title={title} aria-label={title} aria-current={activePage===id?'page':undefined} data-nav-id={id} className={`${activePage===id?'primary':'secondary'} nav-button`} onClick={()=>navigate(id)}><span className="nav-button-icon"><ReferenceIcon name={id}/></span><span className="nav-button-copy"><span>{title}</span></span></button>;
 return <nav className={`app-nav card ref-navigation ${open?'is-mobile-open':''}`} aria-label="Main navigation"><div className="app-nav-copy"><div><strong><span>NetBot</span>Pro</strong><small>Network Security Monitoring</small></div></div><div className="app-nav-actions"><div className="nav-group nav-group-main"><div className="nav-group-items">{items.map(button)}</div></div><details className="ref-tools"><summary>More tools <ChevronDown size={14}/></summary><div>{extras.map(button)}</div></details></div><div className="app-nav-footer"><span className={`nav-signal-dot is-${healthState}`}/><div><strong>{healthLabel}</strong><small>{version}</small><small>{lastUpdated}</small><small>{streamLabel}</small></div></div></nav>;
}

export function Traffic({timeline,sniffer,compact=false}) {
 const [range,setRange]=useState(24), [hover,setHover]=useState(null), [width,setWidth]=useState(680);const root=useRef(null);
 const [,tick]=useState(0);useEffect(()=>{const timer=setInterval(()=>tick(n=>n+1),1000);return()=>clearInterval(timer);},[]);
 const modelPoints=Kf()?timeline:trafficPoints();
 const end=Math.floor(Date.now()/BUCKET_MS)*BUCKET_MS,start=end-range*60000;
 const points=modelPoints.filter(p=>p.time>=start&&p.time<=end);
 const hasData=points.some(p=>p.packets>0||Object.keys(colors).some(k=>p[k]>0));
 const max=Math.max(.001,...points.flatMap(p=>Object.keys(colors).map(k=>p[k]||0)));
 const magnitude=Math.pow(10,Math.floor(Math.log10(max)));
 const scale=magnitude*([1,2,5,10].find(n=>n*magnitude>=max)||10);
 const small=scale<1, unit=small?'Kb/s':'Mb/s', factor=small?1000:1;
 const left=width<450?66:78,right=12,top=compact?8:12,bottom=compact?26:31,height=compact?146:184,plot=width-left-right,base=height-bottom;
 const X=t=>left+(t-start)/(end-start)*plot,Y=v=>base-Math.min(scale,v)/scale*(base-top);
 useEffect(()=>{const element=root.current;if(!element)return;const observer=new ResizeObserver(()=>setWidth(Math.max(280,element.clientWidth)));observer.observe(element);return()=>observer.disconnect();},[]);
 const selected=points.find(p=>p.time===hover);
 const tickCount=width<450?4:range===24&&width>=600?13:7;
 const ticks=Array.from({length:tickCount},(_,i)=>start+(end-start)*i/(tickCount-1));
 function move(e) {const rect=e.currentTarget.getBoundingClientRect();const px=(e.clientX-rect.left)*width/rect.width;if(px<left||px>width-right){setHover(null);return;}const stamp=start+(px-left)/plot*(end-start);setHover(hoverSample(points,stamp)?.time??null);}
 return <section className="ref-panel ref-traffic"><header><h2>{compact?'Network Traffic':'Live Network Traffic'}</h2><select aria-label="Traffic time window" value={range} onChange={e=>{setRange(Number(e.target.value));setHover(null);}}><option value={1}>Last minute</option><option value={5}>Last 5 minutes</option><option value={24}>Last 24 minutes</option><option value={60}>Last hour</option></select></header><div className="ref-legend">{Object.entries(colors).map(([k,c])=><span key={k}><i style={{background:c}}/>{label(k)}</span>)}</div><div ref={root} className="ref-chart"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Network traffic rates" onPointerMove={move} onPointerLeave={()=>setHover(null)}>
 {Array.from({length:5},(_,i)=>scale*i/4).map(v=><g key={v}><line x1={left} x2={width-right} y1={Y(v)} y2={Y(v)}/><text x={left-9} y={Y(v)+4} textAnchor="end">{v===0?'0':`${Number((v*factor).toPrecision(3))} ${unit}`}</text></g>)}
 {ticks.map((t,i)=><g key={i}><line x1={X(t)} x2={X(t)} y1={top} y2={base}/><text x={X(t)} y={height-8} textAnchor={i===0?'start':i===tickCount-1?'end':'middle'}>{range===1?time(t):time(t).slice(0,5)}</text></g>)}
 {points.map(p=><g key={p.time}>{Object.entries(colors).map(([k,c],i)=>p[k]>0?<rect key={k} className="ref-traffic-bar" x={X(p.time)-2+i*.7} y={Y(p[k])} width={Math.max(.8,Math.min(2,plot/Math.max(points.length,1)/4))} height={base-Y(p[k])} fill={c}/>:null)}</g>)}
 {!hasData&&<text x={left+plot/2} y={top+(base-top)/2} textAnchor="middle">Waiting for traffic</text>}
 {selected&&<line className="ref-crosshair" x1={X(selected.time)} x2={X(selected.time)} y1={top} y2={base}/>}</svg>
 {selected&&<div className="ref-tooltip" style={{left:Math.max(4,Math.min(width-214,X(selected.time)+10))}}><strong>{time(selected.time)}</strong>{Object.entries(colors).map(([k,c])=><div key={k}><i style={{background:c}}/>{label(k)}<b>{(selected[k]*factor).toFixed(2)} {unit}</b></div>)}</div>}</div></section>;
}

export {LiveMonitor} from './LiveMonitor.jsx';
export {Investigate} from './Investigate.jsx';

export function CommandCenter({api,dashboardState='loading',agentsState='loading',sniffer={},timeline=[],alerts=[],agents=[],observability={},onNavigate=()=>{}}) {
 const [queueDetail,setQueueDetail]=useState(false),[queueSample,setQueueSample]=useState(null);
 useEffect(()=>{if(!api?.getMonitoringMetrics)return;let active=true,busy=false;async function sample(){if(busy)return;busy=true;try{const metrics=await api.getMonitoringMetrics();if(active)setQueueSample({metrics,at:Date.now(),error:false});}catch{if(active)setQueueSample(old=>({...old,error:true}));}finally{busy=false;}}sample();const timer=setInterval(sample,1000);return()=>{active=false;clearInterval(timer);};},[api]);
 const [data,setData]=useState({incidents:[],flows:null,metrics:null,alerts:null,dashboard:null,total:null,error:''});
 const [trends,setTrends]=useState({session:null,history:[],previous:null,changes:{}});
 useEffect(()=>{if(!api)return;let active=true,busy=false;async function refresh(){if(busy)return;busy=true;try{
 const results=await Promise.allSettled([api.getIncidents({status:'open',limit:8}),api.getFlowsSummary(),api.getMonitoringMetrics(),api.getAlerts({limit:8,offset:0,only_remote:false}),api.getDashboard(),api.getAgents?api.getAgents():Promise.resolve(null)]);
 if(active)setData(old=>{const names=['incidents','flow summary','health metrics','alerts','dashboard','agents'];const failed=results.flatMap((r,i)=>r.status==='rejected'?[names[i]]:[]);const next={...old,fresh:results.map(r=>r.status==='fulfilled'),revision:(old.revision||0)+1,error:failed.length?`Update failed: ${failed.join(', ')}. Last available data is shown.`:''};const keys=['incidents','flows','metrics','alerts','dashboard','agents'];results.forEach((r,i)=>{if(r.status==='fulfilled'){next[keys[i]]=i===0||i===3?r.value?.items||[]:r.value;if(i===0)next.total=r.value?.total??next.incidents.length;}});return next;});
 }catch{if(active)setData(old=>({...old,error:'Operational data is unavailable.'}));}finally{busy=false;}}refresh();const timer=setInterval(refresh,5000);return()=>{active=false;clearInterval(timer);};},[api]);
 const [,rateTick]=useState(0);useEffect(()=>{const timer=setInterval(()=>rateTick(n=>n+1),1000);return()=>clearInterval(timer);},[]);
 const rates=Kf()?{}:trafficRates();const live={...sniffer,...rates};const flow=data.flows;
 const metrics=mergeHealthMetrics(sniffer.observability,observability,data.dashboard?.observability,data.metrics,queueSample?.metrics);
 if(Kf())timeline=data.dashboard?.traffic_timeline||timeline;
 const incidents=useMemo(()=>data.incidents.map(v=>({...v,src:v.src||addresses(v,'source')[0],dst:v.dst||addresses(v,'destination')[0],description:explanation(v)})),[data.incidents]);const recent=data.alerts??alerts;
 agents=data.agents??agents;
 const online=agents.filter(a=>String(a.status).toLowerCase()==='online').length;
 const high=(flow?.risk_distribution?.high||0)+(flow?.risk_distribution?.critical||0);
 const captureHealth=live.capture_error?'critical':dashboardState!=='success'?'unavailable':live.running?'healthy':'idle';
 const queueState=queueSnapshot(queueSample?.metrics||metrics);
 const queueStale=queueSample?.error || (queueSample?.at && Date.now()-queueSample.at>5000);
 const latest=timeline.filter(p=>p.time>=Date.now()-4000);
 const pps=Number(live.packets_per_second??live.pps??metrics.packets_per_second??latest.reduce((n,p)=>n+Number(p.packets||0),0)/4);
 const sampledPps=Kf()?Number(sniffer.packets_per_second??pps):rates.packets_per_second;
 const session=live.capture_started_at;
 const endpointStats=useMemo(()=>endpointRiskSnapshot(flow),[flow]);
 const endpoints=endpointStats.items;
 useEffect(()=>{
  setTrends(old=>{
   const base=old.session===session?old:{session,history:[],previous:null,changes:{}};
   if(!data.revision||data.dashboard?.state?.capture_started_at!==session)return base;
   if(base.revision===data.revision)return base;
   const fresh=data.fresh||[],current={pps:fresh[4]&&dashboardState==='success'?sampledPps:null,incidents:fresh[0]?data.total:null,high:fresh[1]?high:null};
   const changes={pps:metricChange(current.pps,base.previous?.pps,{percentage:true}),incidents:metricChange(current.incidents,base.previous?.incidents,{increaseBad:true}),high:metricChange(current.high,base.previous?.high,{increaseBad:true})};
   return {session,revision:data.revision,previous:current,changes};
  });
 },[data,session,high,dashboardState,sampledPps]);
 const protocol=protocolDistribution(flow);
 const processingHealth=ProcessingHealth(metrics);
 const health= captureHealth==='healthy'&&['critical','degraded','warning','failed','error'].includes(processingHealth)?processingHealth:captureHealth;
 const healthRows=[['Capture Engine',captureHealth],['Network Interfaces',live.running?'healthy':live.capture_error?'critical':'idle'],['Packet Processing',processingHealth],['Disk Storage',HealthValue(metrics.persistence||metrics.storage)],['Database',HealthValue(metrics.persistence||metrics.database)],['Alert Engine',HealthValue(metrics.alert_engine)],['Threat Intelligence',HealthValue(metrics.threat_intelligence)],['License Status','not configured']];
 const captureHint=live.capture_error|| (captureHealth==='idle'?'Capture stopped':captureHealth==='unavailable'?'Checking capture':health==='healthy'?'Capture and processing healthy':`Packet processing ${processingHealth}; capture active`);
 const recentWorkerDrops=Number(metrics.flow_worker_pool?.jobs_dropped_recent||0);
 const queueHint=queueStale?'Stale metrics':recentWorkerDrops?`${num(recentWorkerDrops)} packets dropped in the last minute`:queueState.health;
 const activities=[...incidents.map(v=>({id:v.incident_id,ts:v.last_seen||v.first_seen,title:v.title||v.type||'Incident detected',sub:[...addresses(v,'source'),...addresses(v,'destination')].filter(x=>typeof x==='string').join(' > '),severity:v.severity,target:'incidents'})),...recent.map(v=>({id:`alert-${v.id}`,ts:v.ts||v.timestamp,title:v.attack_type||v.type||'Detection',sub:[v.src,v.dst].filter(Boolean).join(' > '),severity:v.severity,target:'monitor'}))].sort((a,b)=>new Date(b.ts)-new Date(a.ts)).slice(0,7);
 const critical=incidents.filter(v=>v.severity==='critical').length, severe=incidents.filter(v=>v.severity==='high').length;
 const kpis=[{title:'Capture Health',Icon:health==='healthy'?CircleCheck:CircleAlert,value:label(health),hint:captureHint,tone:health==='healthy'?'green':health==='critical'?'red':'muted'},
 {title:'Packets/sec',Icon:ChartNoAxesColumnIncreasing,value:dashboardState==='success'?num(Math.round(pps)):'-',change:trends.changes.pps,hint:`In ${formatTrafficRate(live.inbound_bps)}  Out ${formatTrafficRate(live.outbound_bps)}`,tone:'cyan'},
 {title:'Open Incidents',Icon:CircleAlert,value:data.total===null?'-':num(data.total),change:trends.changes.incidents,hint:`${critical} critical, ${severe} high in view`,tone:'red'},
 {title:'High-risk Flows',Icon:Shield,value:flow?num(high):'-',change:trends.changes.high,hint:'Requiring attention',tone:'red'},
 {title:'Online Agents',Icon:Monitor,value:`${online} / ${agents.length}`,hint:agents.length?`${Math.round(online/agents.length*100)}% online`:'No agents registered',tone:'green'},
 {title:'Queue Pressure',Icon:Database,value:queueState.label,hint:queueHint,tone:'blue'}];
 return <div className="command-center ref-command"><div className="ref-kpis">{kpis.map(({title,Icon,value,hint,tone,change})=><article className={`ref-kpi ${tone}`} key={title}><Icon size={31} className="ref-kpi-icon"/><div><span>{title}</span><div className="ref-kpi-reading"><strong className={title==='Capture Health'?'ref-health-value':''}>{value}</strong>{change&&<span className={`ref-kpi-change ${change.tone} ${change.direction}`} title="Change since the previous successful 5-second sample" aria-label={`${title} change ${change.text}`}>{change.direction!=='flat'&&<Triangle size={10} fill="currentColor"/>}{change.text}</span>}</div><small title={hint}>{hint}</small></div>{title==='Queue Pressure'&&<button className="ref-queue-toggle" title="Queue details" aria-label="Queue details" aria-expanded={queueDetail} onClick={()=>setQueueDetail(v=>!v)}><ChevronDown size={14}/></button>}</article>)}</div>
 {queueDetail&&<section className="ref-panel ref-queue-details" aria-label="Queue details"><header><h2>Queue Pressure</h2><small>{queueStale?'Stale metrics':queueSample?.at?`Updated ${time(queueSample.at)}`:'Metrics unavailable'}</small></header><div className="ref-table-scroll"><table><thead><tr>{['Queue','Depth / Capacity','Current','Peak','Dropped','Failed','Health'].map(value=><th key={value}>{value}</th>)}</tr></thead><tbody>{queueState.rows.map(row=><tr key={row.name}><td>{row.name}</td><td>{row.depth??'-'} / {row.capacity??'-'}</td><td>{pressureLabel(row.percent)}</td><td>{pressureLabel(row.peak)}</td><td>{row.dropped??'-'}</td><td>{row.failed??'-'}</td><td>{label(row.health)}</td></tr>)}</tbody></table></div></section>}
 {data.error&&<p className="ref-error" role="status">{data.error}</p>}
 <div className="ref-primary"><Traffic timeline={timeline} sniffer={live}/><section className="ref-panel ref-incidents"><header><h2>Priority Incidents</h2><button onClick={()=>onNavigate('incidents')}>View All <ArrowRight size={17}/></button></header><div className="ref-table-scroll"><table><thead><tr>{['Time','Severity','Type','Source','Destination','Description'].map(s=><th key={s}>{s}</th>)}</tr></thead><tbody>{incidents.slice(0,6).map(v=><tr key={v.incident_id} tabIndex={0} onKeyDown={e=>e.key==='Enter'&&onNavigate('incidents')} onClick={()=>onNavigate('incidents')}><td>{time(v.last_seen||v.first_seen)}</td><td><Severity value={v.severity}/></td><td title={v.title}>{v.title||label(v.type)}</td><td>{v.src||(v.source_ips||v.sources||[])[0]||'-'}</td><td>{v.dst||(v.destination_ips||v.destinations||[])[0]||'-'}</td><td title={v.description||v.summary}>{v.description||v.summary||v.explanation||'-'}</td></tr>)}</tbody></table></div>{!incidents.length&&<Empty>{data.total===null?'Loading incidents...':'No open incidents'}</Empty>}</section></div>
 <div className="ref-secondary"><Panel title="Network Health" target="settings" onNavigate={onNavigate}><div className="ref-health-list">{healthRows.map(([name,status])=>{const val=String(status).toLowerCase(),ok=['healthy','ok','ready','connected','live'].includes(val),warn=['critical','degraded','warning','failed','error'].includes(val);return <div key={name} className={ok?'healthy':warn?'warning':'neutral'}>{ok?<CircleCheck size={18} fill="currentColor"/>:warn?<TriangleAlert size={18}/>:<Activity size={18}/>}<span>{name}</span><b>{label(val)}</b></div>;})}</div></Panel>
 <Panel title="Top Risky Endpoints" target="inspect" onNavigate={onNavigate}><div className="ref-table-scroll"><table className="ref-endpoints"><thead><tr><th>IP Address</th><th title="Highest detector severity in the current 24-minute window; not proof of a malicious host">Risk</th><th title="Unique detector events in the last 24 minutes; related incidents are not counted again">Events</th><th title="Five completed 5-second intervals">Trend</th></tr></thead><tbody>{endpoints.map(v=>{const samples=v.trend,max=Math.max(1,...samples.filter(value=>value!==null));return <tr key={v.ip}><td title={v.ip}>{v.ip}</td><td><Severity value={v.risk}/></td><td title="Unique detections, current 24-minute window">{v.count}</td><td><div className={`ref-spark ${v.risk}`} role="img" aria-label={`Endpoint detections per 5 seconds: ${samples.map(value=>value??'unavailable').join(', ')}`} title={`Oldest to newest, 5 seconds each: ${samples.map(value=>value??'not observed').join(', ')}`}>{samples.map((count,i)=><i key={i} className={count===null?'missing':count===0?'quiet':''} data-count={count??''} style={{height:`${count===null?2:Math.max(3,18*count/max)}px`}}/>)}</div></td></tr>;})}</tbody></table></div>{!endpointStats.available?<Empty>Endpoint statistics unavailable</Empty>:!endpoints.length?<Empty>No detections in the current window</Empty>:null}{endpointStats.coverage_complete===false&&<p className="ref-data-error" role="status">Endpoint statistics are partial: tracking capacity was reached.</p>}</Panel>
 <Panel title="Protocol Distribution" target="flows" onNavigate={onNavigate}><div className="ref-protocols">{protocol.map((v,i)=><div key={v.protocol}><span title={v.protocol}>{v.protocol}</span><div><i style={{width:`${v.percentage}%`,background:['#008ee7','#008bd0','#00a9df','#00b7bd','#00b0b5','#00b55a','#00b965','#50778d'][i]}}/></div><b>{v.percentage.toFixed(1)}%</b></div>)}</div>{!protocol.length&&<Empty>No captured flows</Empty>}</Panel>
 <Panel title="Agent Fleet" target="agents" onNavigate={onNavigate}><div className="ref-table-scroll"><table><thead><tr><th>Agent</th><th>Status</th><th>Version</th></tr></thead><tbody>{agents.slice(0,10).map(a=><tr key={a.agent_id}><td title={a.hostname||a.display_name}>{a.display_name||a.hostname||a.agent_id}</td><td className={a.status==='online'?'ref-online':'ref-offline'}><i/>{label(a.status)}</td><td>{a.version||a.agent_version||'-'}</td></tr>)}</tbody></table></div>{!agents.length&&<Empty>{agentsState==='error'?'Fleet unavailable':'No agents registered'}</Empty>}</Panel>
 <Panel title="Recent Activity" target="incidents" onNavigate={onNavigate}><div className="ref-activity">{activities.map((v,i)=><button key={`${v.id}-${i}`} onClick={()=>onNavigate(v.target)}><i className={v.severity||'info'}/><time>{time(v.ts)}</time><span>{v.title}<small>{v.sub}</small></span></button>)}</div>{!activities.length&&<Empty>No recent detections</Empty>}</Panel></div></div>;
}
