import React,{useEffect,useMemo,useRef,useState} from 'react';
import {Search,Filter,Check,ChevronLeft,ChevronRight,ArrowRight,ExternalLink,X,PanelRightOpen,EthernetPort,ChevronDown,Plus,ShieldAlert,Info} from 'lucide-react';
import {Traffic} from './CommandCenter.jsx';
import {packetTime,packetRisk,packetProtocol,packetInfo,flowRows,orderedEvidence,evidenceDate,capturedDissection,destinationDomain} from './monitorModel.js';
import {resolveCaptureInterface,captureInterfaceLabel} from './dashboardModel.js';
import {useWindowedRows} from '../src/hooks/useWindowedRows.js';

const title=value=>String(value??'').replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());
const count=value=>Number(value||0).toLocaleString('en-US');
function activateRow(event,action) {
 if(event.target===event.currentTarget&&(event.key==='Enter'||event.key===' ')){event.preventDefault();action();}
}
function IconButton({label,Icon,onClick,disabled=false,expanded}) {
 return <button type="button" className="lm-icon" title={label} aria-label={label} aria-expanded={expanded} onClick={onClick} disabled={disabled}><Icon size={17}/></button>;
}
function Risk({value,alert=false}) {
 const text=alert?(value==='critical'?'Critical':['high','medium','warning'].includes(value)?'Warning':'Info'):title(value);
 const tone=alert?(text==='Critical'?'critical':text==='Warning'?'warning':'info'):value;
 const Icon=tone==='critical'?Plus:tone==='warning'?ShieldAlert:Info;
 return <span className={`lm-risk ${tone}`} title={alert?`Severity: ${value}`:title(value)}>{alert&&<Icon size={11}/>} {text}</span>;
}
function KeyValues({rows}) {
 return <dl className="lm-kv">{rows.map(([name,value])=><div key={name}><dt>{name}</dt><dd>{value===undefined||value===null||value===''?'-':String(value)}</dd></div>)}</dl>;
}
function Fold({title:heading,children,open=true}) {
 return <details className="lm-fold" open={open}><summary>{heading}<ChevronDown size={16}/></summary>{children}</details>;
}
function EmptyRows({columns,loading,error,empty}) {
 return <tr><td colSpan={columns} className="lm-empty" role={error?'alert':undefined}>{error|| (loading?'Loading...':empty)}</td></tr>;
}
function Pager({meta,rows,pageSize,loading,onPaginate,liveFollow,onToggleFollow}) {
 const total=Number(meta.total||0),offset=Number(meta.offset||0);
 return <footer className="lm-pager"><span>{total&&rows?`Showing ${offset+1}-${Math.min(offset+rows,total)} of ${count(total)}`:rows?`Showing ${count(rows)} packets`:'0 results'}<small>{meta.source?` / ${meta.source}`:''}</small></span><div>{onToggleFollow&&<label className="lm-follow">Auto-follow: {liveFollow?'On':'Off'}<input type="checkbox" role="switch" aria-label="Auto-follow" checked={!!liveFollow} disabled={loading} onChange={event=>onToggleFollow(event.target.checked)}/></label>}<button type="button" disabled={loading||offset<=0} onClick={()=>onPaginate(-1)}><ChevronLeft size={14}/>Prev</button><button type="button" disabled={loading||offset+pageSize>=total} onClick={()=>onPaginate(1)}>Next<ChevronRight size={14}/></button></div></footer>;
}
function PacketTable({packets,meta,capturedTotal,query,selectedId,loading,error,focusedTarget,onClearFocus,onChange,onApply,onPaginate,onSelect,onTrack,liveFollow,onToggleFollow,pageSize}) {
 const [advanced,setAdvanced]=useState(false);
 const ordered=useMemo(()=>orderedEvidence(packets),[packets]);
 const sorted=useMemo(()=>ordered.map(entry=>entry.item),[ordered]);
 const selectOriginal=onSelect;
 onSelect=(item,index)=>selectOriginal(item,ordered[index].index);
 const protocols=useMemo(()=>[...new Set(['TCP','UDP','ICMP','DNS','HTTP','HTTPS','TLS','ARP','SSDP','MDNS',...packets.flatMap(packet=>[packet.proto,packet.app_protocol]),query.proto].filter(Boolean))],[packets,query.proto]);
 const {visibleItems,startIndex,topSpacerHeight,bottomSpacerHeight,onScroll}=useWindowedRows(sorted,{enabled:packets.length>60,rowHeight:25,containerHeight:375,resetKey:JSON.stringify({offset:meta.offset,query})});
 return <section className="lm-packets lm-panel"><header><h2>Packets <span>({count(!focusedTarget?.ip&&!Object.entries(query).some(([key,value])=>key!=='only_remote'&&!!value)?capturedTotal??meta.total:meta.total)})</span></h2><form className="lm-filters" onSubmit={event=>{event.preventDefault();onApply();}}><label className="lm-search"><Search size={16}/><input aria-label="Search packets" placeholder="Search packets..." value={query.text||''} onChange={event=>onChange('text',event.target.value)}/></label><IconButton label="More packet filters" Icon={Filter} expanded={advanced} onClick={()=>setAdvanced(!advanced)}/><select aria-label="Protocol filter" value={query.proto||''} onChange={event=>onChange('proto',event.target.value)}><option value="">All Protocols</option>{protocols.map(protocol=><option key={protocol}>{protocol}</option>)}</select><select aria-label="Risk filter" value={query.only_alerts?'alerts':'all'} onChange={event=>onChange('only_alerts',event.target.value==='alerts')}><option value="all">All Risk</option><option value="alerts">Alerts only</option></select><IconButton label="Apply packet filters" Icon={Check} onClick={onApply} disabled={loading}/></form></header>
 {advanced&&<div className="lm-advanced">{[['src','Source IP'],['dst','Destination IP'],['process','Process'],['pid','PID']].map(([key,name])=><label key={key}>{name}<input aria-label={`${name} filter`} value={query[key]||''} onChange={event=>onChange(key,event.target.value)}/></label>)}<label className="lm-checkbox"><input type="checkbox" checked={!!query.only_remote} onChange={event=>onChange('only_remote',event.target.checked)}/>Remote traffic only</label></div>}
 {focusedTarget?.ip&&<p className="lm-focus">Focused endpoint: {focusedTarget.ip} <button type="button" onClick={onClearFocus}>Clear focus</button></p>}
 <div className="lm-table-scroll lm-packet-scroll" onScroll={onScroll}><table><colgroup>{['12%','14%','14%','16%','9%','8%','9%','18%'].map((width,index)=><col key={index} style={{width}}/>)}</colgroup><thead><tr>{['Time','Source','Destination','Destination domain','Protocol','Length','Risk','Info'].map(name=><th key={name}>{name}</th>)}</tr></thead><tbody>
 {!packets.length||error?<EmptyRows columns={8} loading={loading} error={error} empty={focusedTarget?.ip?'No packets match the focused endpoint':meta.total&&meta.offset?'No packets on this page':'No packets match the current filters'}/>:null}
 {!error&&topSpacerHeight>0&&<tr aria-hidden="true"><td colSpan={8} style={{height:topSpacerHeight,padding:0}}/></tr>}
 {!error&&visibleItems.map((packet,index)=>{const absolute=startIndex+index,id=String(packet.id??Number(meta.offset||0)+absolute),domain=destinationDomain(packet);return <tr key={id} tabIndex={0} aria-selected={selectedId===id} className={selectedId===id?'is-selected':''} onClick={()=>onSelect(packet,absolute)} onKeyDown={event=>activateRow(event,()=>onSelect(packet,absolute))}><td title={String(packet.ts||'')}>{packetTime(packet.ts)}</td><td><button className="lm-table-link" title={`Track ${packet.src}`} onClick={event=>{event.stopPropagation();onTrack(packet,'src');}}>{packet.src||'-'}</button></td><td><button className="lm-table-link" title={`Track ${packet.dst}`} onClick={event=>{event.stopPropagation();onTrack(packet,'dst');}}>{packet.dst||'-'}</button></td><td title={[domain.source,...domain.candidates].filter(Boolean).join(' | ')||domain.domain}>{domain.domain}</td><td title={`Transport: ${packet.proto||'-'}`}>{packetProtocol(packet)}</td><td>{packet.length??packet.size??packet.bytes??'-'}</td><td><Risk value={packetRisk(packet)}/></td><td title={packetInfo(packet)}>{packetInfo(packet)}</td></tr>;})}
 {!error&&bottomSpacerHeight>0&&<tr aria-hidden="true"><td colSpan={8} style={{height:bottomSpacerHeight,padding:0}}/></tr>}
 </tbody></table></div><Pager meta={meta} rows={packets.length} pageSize={pageSize} loading={loading||!!error} onPaginate={onPaginate} liveFollow={liveFollow} onToggleFollow={onToggleFollow}/></section>;
}
function AlertTable({alerts,meta,query,selectedId,loading,error,onChange,onApply,onPaginate,onSelect,onTrack,pageSize,onNavigate}) {
 const [filters,setFilters]=useState(false);
 return <section className="lm-alerts lm-panel"><header><h2>Active Alerts <span>({count(meta.total)})</span></h2><div><IconButton label="Alert filters" Icon={Filter} expanded={filters} onClick={()=>setFilters(!filters)}/><button className="lm-view-all" onClick={()=>onNavigate('inspect')}>View All Alerts<ArrowRight size={16}/></button></div></header>
 {filters&&<form className="lm-advanced" onSubmit={event=>{event.preventDefault();onApply();}}>{[['text','Search alerts'],['src','Alert source'],['attack','Alert type'],['proto','Alert protocol'],['process','Alert process'],['pid','Alert PID'],['min_score','Minimum risk score']].map(([key,name])=><label key={key}>{name}<input aria-label={name} value={query[key]||''} onChange={event=>onChange(key,event.target.value)}/></label>)}<label className="lm-checkbox"><input type="checkbox" checked={!!query.only_remote} onChange={event=>onChange('only_remote',event.target.checked)}/>Remote traffic only</label><IconButton label="Apply alert filters" Icon={Check} onClick={onApply} disabled={loading}/></form>}
 <div className="lm-table-scroll lm-alert-scroll"><table><colgroup>{['11%','9%','15%','16%','16%','33%'].map((width,index)=><col key={index} style={{width}}/>)}</colgroup><thead><tr>{['Severity','Time','Type','Source','Destination','Description'].map(name=><th key={name}>{name}</th>)}</tr></thead><tbody>
 {!alerts.length||error?<EmptyRows columns={6} loading={loading} error={error} empty="No active alerts"/>:null}
 {!error&&alerts.map((alert,index)=>{const id=String(alert.id??Number(meta.offset||0)+index);return <tr key={id} tabIndex={0} aria-selected={selectedId===id} className={selectedId===id?'is-selected':''} onClick={()=>onSelect(alert,index)} onKeyDown={event=>activateRow(event,()=>onSelect(alert,index))}><td><Risk alert value={String(alert.severity||'info').toLowerCase()}/></td><td title={String(alert.ts||'')}>{packetTime(alert.ts,false)}</td><td title={alert.attack_type||alert.type}>{alert.attack_type||alert.type||'-'}</td><td><button className="lm-table-link" onClick={event=>{event.stopPropagation();onTrack(alert,'src');}}>{alert.src||'-'}</button></td><td><button className="lm-table-link" onClick={event=>{event.stopPropagation();onTrack(alert,'dst');}}>{alert.dst||'-'}</button></td><td title={alert.description||alert.detail||alert.summary}>{alert.description||alert.detail||alert.summary||'-'}</td></tr>;})}
 </tbody></table></div>{Number(meta.total)>alerts.length&&<Pager meta={meta} rows={alerts.length} pageSize={pageSize} loading={loading||!!error} onPaginate={onPaginate}/>}</section>;
}
export function Inspector({api,packet,alert,packetModel,onClose,onOpen,onPrevious,onNext,canPrevious,canNext,loading,error,canOpen=true,heading,hideFooter=false,extraContent,primaryContent,evidenceOpen=true}) {
 const [detail,setDetail]=useState({id:null,value:null,error:'',loading:false});
 const cache=useRef(new Map());
 const captured=useRef(packet);
 captured.current=packet;
 const id=packet?.id;
 const cacheKey=`${id}:${packet?.ts??packet?.timestamp??''}`;
 useEffect(()=>{
  if(!id||!api?.getPacketDissection)return;
  let active=true;
  const snapshot=captured.current;
  setDetail({id,value:cache.current.get(cacheKey)||null,error:'',loading:true});
  api.getPacketDissection(id).then(value=>{
   if(!active)return;
   cache.current.set(cacheKey,{...value,hex:{rows:[],warning:'Cached metadata only; raw bytes are not retained.'}});
   if(cache.current.size>64)cache.current.delete(cache.current.keys().next().value);
   setDetail({id,value,error:'',loading:false});
  }).catch(()=>{
   if(active)setDetail({id,value:cache.current.get(cacheKey)||capturedDissection(snapshot),error:'Full protocol dissection unavailable; captured metadata is shown.',loading:false});
  });
  return()=>{active=false;};
 },[id,cacheKey,api]);
 const dissection=detail.id===id?detail.value:null;
 const item=packet||alert;
 const risk=packetRisk(item);
 const evidence=(packetModel?.flowRows||[]).filter(row=>['First Seen','Packets In Flow','Last Seen'].includes(row.label));
 return <aside className="lm-inspector lm-panel" aria-label={heading||'Packet Inspector'}><header><h2>{heading||(packet?'Packet Inspector':alert?'Alert Inspector':'Packet Inspector')}</h2><IconButton label={heading?'Close technical inspector':'Close packet inspector'} Icon={X} onClick={onClose}/></header><div className="lm-inspector-body">
 {!item?<p className="lm-empty">No packet selected</p>:<><div className="lm-verdict"><span className={`lm-verdict-risk ${risk}`}><ShieldAlert size={16}/>{title(risk)} Risk</span><span>{alert?.attack_type||packetInfo(item)}</span></div><KeyValues rows={[
 ['Time',packetTime(item.ts??item.timestamp)],['Source',item.src],['Destination',item.dst],['Destination domain',destinationDomain(item).domain],['Domain evidence',destinationDomain(item).source],['Possible domains',destinationDomain(item).candidates.join(', ')],['Protocol',packetProtocol(item)],['Length',packet?.length!==undefined?`${packet.length} bytes`:null],['Info',packetInfo(item)]]}/>
 {(loading||error)&&<p className="lm-notice" role={error?'alert':undefined}>{error||'Loading packet detail...'}</p>}
 <Fold title="Flow Details"><KeyValues rows={flowRows(item)}/></Fold>
 <Fold title="Protocol Layers">{detail.id===id&&detail.error&&<p className="lm-notice" role="status">{detail.error}</p>}{detail.id===id&&detail.loading&&!dissection?<p className="lm-notice">Loading protocol layers...</p>:dissection?.layers?.length?dissection.layers.map((layer,index)=><details key={`${layer.name}-${index}`} className="lm-layer" open={['TCP','UDP','ICMP'].includes(layer.name)}><summary>{layer.name}<span>{layer.name==='Frame'&&packet?.length!==undefined?` (${packet.length} bytes)`:''}</span></summary><KeyValues rows={(layer.fields||[]).map(field=>[field.label,field.display_value??field.value])}/></details>):<p className="lm-notice">No decoded layers available</p>}</Fold>
 {typeof primaryContent==='function'?primaryContent(dissection):primaryContent}
 <Fold title="Evidence" open={evidenceOpen}><KeyValues rows={[
 ...evidence.map(row=>[row.label,['First Seen','Last Seen'].includes(row.label)?evidenceDate(row.value):row.value]),
 ['Related alerts',dissection?.related_alert_ids?.length??(packet?.is_alert?'Present':'-')],
 ['Geolocation',[item.country,item.asn].filter(Boolean).join(' / ')||null],
 ['Detection',alert?.attack_type],['Engine',alert?.engine],
 ]}/></Fold>
 {(item.process_name||item.pid||packetModel?.processRows?.some(row=>row.value&&row.value!=='-'))&&<Fold title="Process" open={false}><KeyValues rows={packetModel?.processRows?.length?packetModel.processRows.map(row=>[row.label,row.value]):[['Process',item.process_name],['PID',item.pid]]}/></Fold>}
 {(packetModel?.applicationGroups||[]).map(group=><Fold title={group.title} key={group.title} open={false}><KeyValues rows={(group.rows||[]).map(row=>[row.label,row.value])}/></Fold>)}
 {dissection?.expert_items?.length>0&&<Fold title="Expert Information" open={false}>{dissection.expert_items.map((expert,index)=><p className="lm-notice" key={index}>{expert.message||expert.summary||expert.category}</p>)}</Fold>}
 {typeof extraContent==='function'?extraContent(dissection):extraContent}
 </>}
 </div>{item&&!hideFooter&&<div className="lm-inspector-actions">{packet&&<><IconButton label="Previous packet" Icon={ChevronLeft} onClick={onPrevious} disabled={!canPrevious}/><IconButton label="Next packet" Icon={ChevronRight} onClick={onNext} disabled={!canNext}/></>}<button className="lm-open-investigate" disabled={loading||!!error||!canOpen} onClick={onOpen}><ExternalLink size={16}/>Open in Investigate</button></div>}</aside>;
}

export function LiveMonitor(props) {
 const {api,packets=[],alerts=[],packetMeta={},alertMeta={},packetQuery={},alertQuery={},packet,alert,packetModel,selectedPacketId,selectedAlertId,sniffer={},timeline=[],interfaces=[],settings={},liveFollow,focusedTarget,isLoading={},resourceError='',resourceState,onPacketQueryChange,onApplyPacketFilters,onPaginatePackets,onSelectPacket,onTrackTarget,onClearFocusedTarget,onToggleFollow,onAlertQueryChange,onApplyAlertFilters,onPaginateAlerts,onSelectAlert,pageSize=25,onNavigate,packetDetailLoading,packetDetailError}=props;
 const [closed,setClosed]=useState(false),[candidate,setCandidate]=useState(null),[mode,setMode]=useState('packet');
 const effectivePacket=mode==='packet'&&selectedPacketId?(candidate&&String(candidate.id)===String(selectedPacketId)?candidate:packet&&String(packet.id)===String(selectedPacketId)?packet:null):null;
 const navigationOrder=useMemo(()=>orderedEvidence(packets),[packets]);
 const index=navigationOrder.findIndex(({item})=>String(item.id)===String(effectivePacket?.id));
 const selectPacket=(item,position)=>{setCandidate(item);setMode('packet');setClosed(false);onSelectPacket(item,position,{navigate:false});};
 const selectAlert=(item,position)=>{setCandidate(null);setMode('alert');setClosed(false);onSelectAlert(item,position,{navigate:false});};
 const active=resolveCaptureInterface(interfaces,sniffer.iface||settings.iface);
 const error=resourceState==='error'?resourceError||'Live data unavailable':'';
 return <section className={`ref-monitor ${closed?'inspector-closed':''}`}><div className="lm-main"><header className="lm-title lm-panel"><h1>Live Monitor</h1><button title="Change capture adapter" onClick={()=>onNavigate('settings')}><EthernetPort size={17}/>{active?captureInterfaceLabel(active).name:sniffer.iface||settings.iface||'iface-default'}<ChevronDown size={16}/></button>{closed&&<IconButton label="Open packet inspector" Icon={PanelRightOpen} onClick={()=>setClosed(false)}/>}</header>
 <Traffic timeline={timeline} sniffer={sniffer} compact/>
 <PacketTable packets={packets} meta={packetMeta} capturedTotal={sniffer.total_packets} query={packetQuery} selectedId={selectedPacketId} loading={isLoading.packets} error={error} focusedTarget={focusedTarget} onClearFocus={onClearFocusedTarget} onChange={onPacketQueryChange} onApply={onApplyPacketFilters} onPaginate={onPaginatePackets} onSelect={selectPacket} onTrack={onTrackTarget} liveFollow={liveFollow} onToggleFollow={onToggleFollow} pageSize={pageSize}/>
 <AlertTable alerts={alerts} meta={alertMeta} query={alertQuery} selectedId={selectedAlertId} loading={isLoading.alerts} error={error} onChange={onAlertQueryChange} onApply={onApplyAlertFilters} onPaginate={onPaginateAlerts} onSelect={selectAlert} onTrack={onTrackTarget} pageSize={pageSize} onNavigate={onNavigate}/>
 </div>{!closed&&<Inspector api={api} packet={effectivePacket} alert={mode==='alert'&&selectedAlertId?alert:null} packetModel={mode==='packet'&&String(effectivePacket?.id)===String(packet?.id)?packetModel:null} canOpen={mode==='packet'?!!packet&&String(effectivePacket?.id)===String(packet.id):!!alert&&String(alert.id)===String(selectedAlertId)} onClose={()=>setClosed(true)} onOpen={()=>onNavigate('inspect')} onPrevious={()=>{const entry=navigationOrder[index-1];if(entry)selectPacket(entry.item,entry.index);}} onNext={()=>{const entry=navigationOrder[index+1];if(entry)selectPacket(entry.item,entry.index);}} canPrevious={index>0} canNext={index>=0&&index<navigationOrder.length-1} loading={packetDetailLoading} error={packetDetailError}/>}</section>;
}
