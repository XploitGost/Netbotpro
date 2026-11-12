import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';
import {CommandCenter, Navigation, Topbar} from './CommandCenter.jsx';
import {LiveMonitor} from './LiveMonitor.jsx';
import {Investigate} from './Investigate.jsx';
import {AgentsPanel} from './Fleet.jsx';
import '../src/styles.css';
import './reference.css';
import './fleet.css';
import './endpoint-focus.css';
import './docs-shell.css';
import {capturedDissection} from './monitorModel.js';
import {DesktopRuntime} from '../src/desktop/DesktopRuntime.jsx';

// Synthetic fixtures are confined to this documentation entry.
const now = Date.now();
const noop = () => {};
const interfaces = [{name:'Ethernet Demo',value:'demo0',label:'Ethernet Demo',is_up:true,recommended:true}];
const packets = Array.from({length:25}, (_,i) => ({id:`demo-${i}`,ts:new Date(now-i*240).toISOString(),
  src:i%2?'192.0.2.24':'203.0.113.77',dst:i%2?'203.0.113.77':'192.0.2.24',
  proto:i%5===0?'UDP':'TCP',app_protocol:i%5===0?'DNS':'TLS',length:80+i*37,sport:i%2?52000:443,
  dport:i%2?443:52000,flags:'A',seq:1024+i,ack:2048,window:64240,ttl:64,
  direction:i%2?'outgoing':'incoming',risk_level:i===3?'high':'low',process_name:'browser.exe',
  destination_domain:'example.net',destination_domain_source:'TLS SNI',summary:i%5===0?'Standard DNS query example.net':'TLS application data',flow_id:'demo-flow'}));
packets[3]={...packets[3],proto:'TCP',app_protocol:'TCP',src:'203.0.113.77',dst:'192.0.2.24',sport:49822,dport:80,flags:'S',seq:0,ack:0,direction:'incoming',summary:'SYN connection attempt',destination_domain:'',destination_domain_source:'',length:60};
const alerts = [{id:'demo-alert',ts:new Date(now-3000).toISOString(),src:'203.0.113.77',dst:'192.0.2.24',proto:'TCP',severity:'high',attack_type:'Connection review',detail:'Synthetic alert for documentation; not a real detection.'}];
const sniffer={running:true,iface:'demo0',capture_started_at:now/1000-1457,total_packets:12492,packets_per_second:92,
  inbound_bps:30400000,outbound_bps:12800000,capture_health:'healthy',health:'healthy'};
const timeline=Array.from({length:720},(_,i)=>({time:Math.floor(now/2000)*2000-(719-i)*2000,
  inbound:8+((i*17)%31),outbound:3+((i*11)%14),suspicious:i%79===0?10:0,malicious:i%211===0?4:0,packets:30}));
const metrics={health:'healthy',packet_queue:{health:'healthy',queue_depth:12,max_size:2000,worker_alive:true},
  flow_worker_pool:{health:'healthy',queue_depth_total:2,queue_max_total:2048,worker_alive:true},
  persistence:{health:'healthy',queue_depth:0,queue_max:8192},alert_engine:{health:'healthy'},threat_intelligence:{health:'not_configured'}};
const agents=Array.from({length:20},(_,i)=>({agent_id:`DEMO-${String(i+1).padStart(3,'0')}`,hostname:`LAB-NODE-${String(i+1).padStart(2,'0')}`,
  ip_address:`192.0.2.${i+10}`,status:i%7===6?'offline':'online',last_seen:new Date(now-i*1000).toISOString(),agent_version:'0.2.0',
  risk:{severity:i===5?'high':i%3===0?'medium':'low',score:i===5?74:i%3===0?42:12},
  last_telemetry:{capture:{total_packets:120000+i*17000},health:{cpu_percent:18,memory_percent:37,disk_percent:41},
    alerts_summary:{total_alerts:i%4,recent_alerts:i===5?alerts:[]},network:{inbound_bps:1040000,outbound_bps:210000}}}));
const incidents=[{incident_id:'demo-incident',title:'Connection review',severity:'high',status:'open',
  source_hosts:['203.0.113.77'],destination_hosts:['192.0.2.24'],description:'Synthetic investigation example',last_seen:new Date(now).toISOString()}];
const flows={total_flows:120,high_risk_flows:1,risk_distribution:{high:1,low:119},top_protocols:[{protocol:'TLS',count:80},{protocol:'TCP',count:20},{protocol:'DNS',count:15},{protocol:'UDP',count:5}],
  endpoint_risk:{scope:'detector_events',coverage_complete:true,items:[{ip:'203.0.113.77',risk:'high',count:3,trend:[0,1,0,1,1]}]}};
const model={analystCards:[{label:'Destination Service',value:'HTTP (80)',hint:'Port-based hint only'},
  {label:'Risk',value:'High'},{label:'Why It Matters',value:'Review this connection using packet, flow and host context. A single SYN is not proof of an attack.'}],
  riskExplanation:{groups:[{title:'Observed evidence',items:[{title:'Inbound TCP SYN to service port 80'},{title:'No payload is exposed in this metadata example'}]}]}};
const api={getIncidents:async()=>({items:incidents,total:1}),getFlowsSummary:async()=>flows,
  getMonitoringMetrics:async()=>metrics,getAlerts:async()=>({items:alerts,total:1}),getDashboard:async()=>({state:sniffer,observability:metrics}),
  getAgents:async()=>agents,getPacketDissection:async id=>capturedDissection(packets.find(p=>p.id===id))};
function App(){
  const [page,setPage]=useState(new URLSearchParams(location.search).get('page')||'command');
  const [packet,setPacket]=useState(packets[3]);
  const common={api,packets,alerts,packet,packetModel:model,selectedPacketId:packet.id,
    packetMeta:{total:packets.length,offset:0,limit:25,source:'fixture'},alertMeta:{total:1},
    onSelectPacket:setPacket,onSelectAlert:noop,onPaginatePackets:noop,onPaginateAlerts:noop};
  return <div className="shell docs-shell"><Navigation activePage={page} onNavigate={setPage} healthLabel="Synthetic preview" version="v0.2.0-dev" streamLabel="No live network data"/>
    <Topbar fixtureMode backendState="connected" dashboardState="success" sniffer={sniffer} interfaces={interfaces} connectionLabel="Connected" canStartSniffer={false}/>
    <main className="soc-main">
      {page==='command'&&<><header className="workspace-header"><h1>Command Center</h1><p>Operational Overview</p></header><CommandCenter api={api} dashboardState="success" agentsState="success" sniffer={sniffer} timeline={timeline} alerts={alerts} agents={agents} observability={metrics} onNavigate={setPage}/></>}
      {page==='monitor'&&<LiveMonitor {...common} sniffer={sniffer} timeline={timeline} interfaces={interfaces} resourceState="success" liveFollow onNavigate={setPage} onToggleFollow={noop} onPacketQueryChange={noop} onApplyPacketFilters={noop} onAlertQueryChange={noop} onApplyAlertFilters={noop}/>}
      {page==='inspect'&&<Investigate {...common} packetNavigation={{hasNext:true}} actions={null} renderFocus={()=>null}/>}
      {page==='agents'&&<AgentsPanel agents={agents} selectedAgentId="DEMO-006" overview={{demo_data:true}} onRefresh={noop} onExportFleetSummary={noop} agentHealthHistory={Array.from({length:36},()=>({received_at:new Date(now).toISOString(),cpu_percent:18}))}/>}
    </main></div>;
}
createRoot(document.getElementById('root')).render(<DesktopRuntime fixtureMode><App/></DesktopRuntime>);
