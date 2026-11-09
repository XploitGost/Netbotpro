import fs from 'node:fs';
import path from 'node:path';
import {build} from 'esbuild';
const desktop=process.env.NETBOT_DESKTOP_FRONTEND;
const output=path.resolve('preview');
const baseline=path.resolve('.baseline');
if(!fs.existsSync(baseline)){
 if(!desktop)throw new Error('Set NETBOT_DESKTOP_FRONTEND to a compatible frontend baseline; see README.md');
 fs.cpSync(desktop,baseline,{recursive:true});
}
fs.mkdirSync(output,{recursive:true});
fs.cpSync(baseline,output,{recursive:true});
const shim=`const React=L; export default React; export const {createElement,forwardRef,memo,useEffect,useMemo,useRef,useState,Fragment}=React;`;
const compiled=await build({entryPoints:['CommandCenter.jsx'],bundle:true,write:false,format:'iife',globalName:'NetBotReference',minify:true,plugins:[{name:'existing-react',setup(b){b.onResolve({filter:/^react$/},()=>({path:'shared-react',namespace:'shared'}));b.onLoad({filter:/.*/,namespace:'shared'},()=>({contents:shim,loader:'js'}));}}]});
const bundle=path.join(output,'assets/index-B8rp-3mx.js');
let source=fs.readFileSync(bundle,'utf8');
const begin=source.indexOf('function Jp('),end=source.indexOf('function Le(',begin);
if(begin<0||end<0)throw new Error('Installed Command Center boundary changed');
source=source.slice(0,begin)+compiled.outputFiles[0].text+'\nfunction Jp(props){return s.jsx(NetBotReference.CommandCenter,props)}'+source.slice(end);
const iconStart=source.indexOf('function zr('),iconEnd=source.indexOf('const Wp=',iconStart);
if(iconStart<0||iconEnd<0)throw new Error('Icon boundary changed');
const originalIcon=source.slice(iconStart,iconEnd).replace('function zr(','function OriginalNetBotIcon(');
source=source.slice(0,iconStart)+originalIcon+'function zr(props){return s.jsx(NetBotReference.ReferenceIcon,props)}'+source.slice(iconEnd);
const navStart=source.indexOf('function qp('),navEnd=source.indexOf('function Ur(',navStart);
const topStart=source.indexOf('function Zy('),topEnd=source.indexOf('function Jy(',topStart);
if(navStart<0||navEnd<0||topStart<0||topEnd<0)throw new Error('Shared shell boundary changed');
source=source.slice(0,topStart)+'function Zy(props){return s.jsx(NetBotReference.Topbar,props)}'+source.slice(topEnd);
if(!source.includes('s.jsx(Zy,{fixtureMode:h,'))throw new Error('Topbar API injection boundary changed');
source=source.replace('s.jsx(Zy,{fixtureMode:h,','s.jsx(Zy,{api:p,fixtureMode:h,');
const monitorStart=source.indexOf('const Kt=s.jsxs("section",{className:`soc-monitor-grid');
const monitorEnd=source.indexOf(',Je=s.jsx(',monitorStart);
if(monitorStart<0||monitorEnd<0)throw new Error('Live Monitor boundary changed');
source=source.slice(0,monitorStart)+'const Kt=s.jsx(NetBotReference.LiveMonitor,{api:p,packets:b,alerts:E,packetMeta:F,alertMeta:H,packetQuery:j,alertQuery:w,packet:I,alert:S,packetModel:bt,selectedPacketId:te,selectedAlertId:k,sniffer:wt,timeline:Qn,interfaces:Y,settings:se,liveFollow:Rt,focusedTarget:dn,isLoading:Ve,resourceState:qe.dashboard,resourceError:Nt.dashboard,onPacketQueryChange:De,onApplyPacketFilters:Pe,onPaginatePackets:yn,onSelectPacket:Pt,onTrackTarget:gs,onToggleFollow:Kn,onAlertQueryChange:vt,onApplyAlertFilters:sn,onPaginateAlerts:Jn,onSelectAlert:hn,pageSize:yt,onNavigate:m,packetDetailLoading:Ve.packetDetail,packetDetailError:Nt.packetDetail})'+source.slice(monitorEnd);
source=source.replace('onTrackTarget:gs,onToggleFollow:Kn','onTrackTarget:gs,onClearFocusedTarget:vn,onToggleFollow:Kn');
const inspectStart=source.indexOf('bs=s.jsxs("section",{className:`investigation-layout page-grid-inspect');
const inspectEnd=source.indexOf(',je=s.jsx("section",{className:"page-grid page-grid-single"',inspectStart);
if(inspectStart<0||inspectEnd<0)throw Error('Investigation boundary changed');
source=source.slice(0,inspectStart)+'bs=s.jsx(NetBotReference.Investigate,{api:p,packets:b,alerts:E,packetMeta:F,alertMeta:H,packet:I,alert:S,packetModel:bt,alertModel:Mt,packetContext:gt,alertContext:_t,selectedPacketId:te,selectedAlertId:k,packetNavigation:ts,alertNavigation:Ge,pinned:G,actions:At,onSelectPacket:Pt,onSelectAlert:hn,onPaginatePackets:yn,onPaginateAlerts:Jn,loading:Ve,errors:Nt,renderDetails:()=>s.jsx(_f,{title:k?"Alert Detail":"Packet Detail",model:k?Mt:bt,selectionKey:k||te,navigation:k?Ge:ts}),renderAdvancedInspector:()=>s.jsx(um,{api:p,packetId:te}),renderIntelligence:()=>s.jsx(Fm,{api:p}),renderFocus:()=>s.jsx(fm,{focusedTarget:dn,focusedPacketCount:Yn,focusedAlerts:Ht,liveFollow:Rt,onClearFocusedTarget:vn,onResumeLive:_s})})'+source.slice(inspectEnd);
source=source.replace('renderFocus:()=>s.jsx(fm,{focusedTarget:dn','focusedTarget:dn,onClearFocusedTarget:vn,renderFocus:()=>s.jsx(fm,{focusedTarget:dn');
for(const name of ['Kr','Qr']){
 const pattern=new RegExp(`async function ${name}\\(\\$,D\\)\\{(.*?)try\\{h\\("inspect"\\);`);
 if(!pattern.test(source))throw new Error('Detail selection boundary changed: '+name);
 source=source.replace(pattern,`async function ${name}($,D,options={}){$1try{if(options.navigate!==false)h("inspect");`);
}
for(const [before,after] of [
 ['J(ie),G(null);','J(ie),te(null),G(null),Fe("");'],
 ['xe(ie),me(null);','xe(ie),Y(null),me(null),Fe("");'],
 ['J(D),G(null);','J(D),te(null),G(null),Fe("");'],
 ['xe(D),me(null);','xe(D),Y(null),me(null),Fe("");'],
]){
 if(!source.includes(before))throw Error('Selection reset boundary changed: '+before);
 source=source.replaceAll(before,after);
}
source=source.slice(0,navStart)+'function qp(props){return s.jsx(NetBotReference.Navigation,props)}'+source.slice(navEnd);
source=source.replace('subtitle:"Operational health, security signals, traffic, and fleet visibility."','subtitle:"Operational Overview"');
const incidentState='function mm({api:t,initialIncidentId:l="",onOpenFlow:i=null,onInspectAlert:a=null}){';
const incidentRequest='const Be=(await t.getIncidents({status:ne,severity:W,limit:200})).items||[];d(Be),';
if(!source.includes(incidentState)||!source.includes(incidentRequest))throw Error('Incident totals boundary changed');
source=source.replace(incidentState,incidentState+'const [incidentTotals,setIncidentTotals]=L.useState(null);');
source=source.replace(incidentRequest,'const incidentResponse=await t.getIncidents({status:ne,severity:W,limit:200});const Be=incidentResponse.items||[];setIncidentTotals(incidentResponse.summary||null);d(Be),');
for(const [before,after] of [['value:A(z.open)','value:A(incidentTotals?.open??z.open)'],['value:A(z.critical)','value:A(incidentTotals?.critical??z.critical)'],['value:A(z.high)','value:A(incidentTotals?.high??z.high)'],['value:A(z.medium)','value:A(incidentTotals?.medium??z.medium)']]){
 if(!source.includes(before))throw Error('Incident metric boundary changed');
 source=source.replace(before,after);
}
if(!source.includes('function monitorSample(packet){'))throw Error('Packet sample hook missing');
source=source.replace('function monitorSample(packet){','function monitorSample(packet){NetBotReference.recordPacket(packet);');
source=source.replaceAll('monitorSamples.clear()','(monitorSamples.clear(),NetBotReference.resetTraffic())');
const packetBatchStart='onPacketsBatch:$=>{bs(),';
const packetBatchRows='y(D=>_t&&Ge.current===0?[...$.map(q=>q.payload),...D].slice(0,yt):D)';
const packetBatchCounter='I(D=>({...D,total:Math.max(D.total+$.length,$.length)}))';
const alertBatchCounter='S(D=>({...D,total:Math.max(D.total+$.length,$.length)}))';
if(!source.includes(packetBatchStart)||!source.includes(packetBatchRows)||!source.includes(packetBatchCounter)||!source.includes(alertBatchCounter))throw Error('Live packet boundary changed');
source=source.replace(packetBatchStart,'onPacketsBatch:$=>{const incomingPackets=$.map(q=>q.payload).filter(q=>livePacketMatchesQuery(q,E));bs(),');
source=source.replace(packetBatchRows,'y(D=>_t&&Ge.current===0?[...incomingPackets,...D].slice(0,yt):D)');
source=source.replace(packetBatchCounter,'I(D=>({...D,total:Math.min(D.total+incomingPackets.length,vt?.live_ring_buffer?.categories?.packet?.capacity||5000)}))');
source=source.replace(alertBatchCounter,'S(D=>_t&&mr.current===0?{...D,total:Math.min(D.total+$.length,vt?.live_ring_buffer?.categories?.alert?.capacity||1000)}:D)');
source=source.replace('onToggleFollow:Kn,onAlertQueryChange:vt','onToggleFollow:enabled=>{Kn(enabled);if(enabled)Pe()},onAlertQueryChange:vt');
source=source.replace('onPaginatePackets:yn,onSelectPacket:Pt','onPaginatePackets:direction=>{if(direction>0)Kn(false);yn(direction)},onSelectPacket:Pt');
const initialPacketMeta='I({total:((ge=Ae.state)==null?void 0:ge.packet_count)||0,source:"memory",offset:0,limit:yt})';
const initialAlertMeta='S({total:((Me=Ae.state)==null?void 0:Me.total_alerts)||0,source:"memory",offset:0,limit:yt})';
if(!source.includes(initialPacketMeta)||!source.includes(initialAlertMeta))throw Error('Initial history count boundary changed');
source=source.replace(initialPacketMeta,'I({total:Ae.observability?.live_ring_buffer?.categories?.packet?.records??Ae.state?.packet_count??0,source:"memory",offset:0,limit:yt})');
source=source.replace(initialAlertMeta,'S({total:Ae.observability?.live_ring_buffer?.categories?.alert?.records??Ae.state?.total_alerts??0,source:"memory",offset:0,limit:yt})');
source=`function livePacketMatchesQuery(packet,query){if(query.src&&!String(packet.src||'').toLowerCase().includes(String(query.src).toLowerCase()))return false;if(query.dst&&!String(packet.dst||'').toLowerCase().includes(String(query.dst).toLowerCase()))return false;if(query.proto&&!String(packet.proto||'').toLowerCase().includes(String(query.proto).toLowerCase()))return false;if(query.process&&![packet.process_name,packet.parent_process_name,packet.executable_path].join(' ').toLowerCase().includes(String(query.process).toLowerCase()))return false;if(query.pid&&String(packet.pid||'').trim()!==String(query.pid))return false;if(query.only_alerts&&!packet.is_alert)return false;if(query.text&&![packet.src,packet.dst,packet.summary,packet.org,packet.country,packet.country_code,packet.remote_ip,packet.app_protocol,packet.l7,packet.dns_qname,packet.destination_domain,...(packet.destination_domain_candidates||[]),packet.http_host,packet.http_path,packet.sni,packet.protocol_basis,packet.protocol_notes,packet.process_name,packet.parent_process_name,packet.executable_path].join(' ').toLowerCase().includes(String(query.text).toLowerCase()))return false;return true;}\n`+source;
const oldServicePort='return l==="OUTGOING"?a||i:l==="INCOMING"?i||a:a||i}function yy(t)';
const newServicePort='return l==="OUTGOING"?a||i:l==="INCOMING"?/S/i.test(String(t?.flags??t?.tcp_flags??""))&&!/A/i.test(String(t?.flags??t?.tcp_flags??""))?a||i:i||a:a||i}function yy(t)';
if(!source.includes(oldServicePort))throw Error('Packet service port boundary changed');
source=source.replace(oldServicePort,newServicePort);
fs.mkdirSync('release/assets',{recursive:true});
fs.writeFileSync('release/assets/index-B8rp-3mx.js',source);
let preview=source.replace('function Kf(){return!1}','function Kf(){return new URLSearchParams(location.search).get("fixture")==="visual"}');
preview=preview.replace('Ym=Array.from({length:30}','Ym=Array.from({length:720}').replaceAll('$n-(29-l)*2e3','$n-(719-l)*2e3');
preview=preview.replace('$n=Date.parse("2026-09-19T14:32:10.000Z")','$n=Date.now()');
fs.writeFileSync(bundle,preview);
fs.copyFileSync('reference.css',path.join(output,'assets/reference.css'));
fs.copyFileSync('reference.css','release/assets/reference.css');
let html=fs.readFileSync(path.join(output,'app.html'),'utf8');
html=html.replace('</head>','<link rel="stylesheet" href="./assets/reference.css">\n</head>');
fs.writeFileSync(path.join(output,'app.html'),html);
fs.writeFileSync(path.join(output,'index.html'),html);
fs.writeFileSync('release/app.html',html);
console.log('Command Center built against the installed runtime; all other modules retained.');
