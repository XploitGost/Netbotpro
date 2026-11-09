import React,{useState,useMemo,useRef,useEffect} from 'react';
import {Crosshair,X} from 'lucide-react';
const KEY='netbotpro:incident-focus';
function readFocus(){try{return JSON.parse(sessionStorage.getItem(KEY)||'null');}catch{return null;}}
function saveFocus(value){try{value?sessionStorage.setItem(KEY,JSON.stringify(value)):sessionStorage.removeItem(KEY);}catch{}}
export function incidentHasEndpoint(row,ip){
 const values=[row.src,row.dst,row.source_host,row.destination_host,...['source_hosts','destination_hosts','source_ips','destination_ips','sources','destinations'].flatMap(key=>Array.isArray(row[key])?row[key]:[])];
 return values.some(value=>String(value||'')===ip);
}
export function CommandBridge({Original,onNavigate,...props}){
 const root=useRef(null);
 useEffect(()=>{const node=root.current;if(!node)return;const update=()=>node.querySelectorAll('.ref-endpoints tbody tr,.ref-incidents tbody tr').forEach(row=>{row.tabIndex=0;});const observer=new MutationObserver(update);observer.observe(node,{childList:true,subtree:true});update();return()=>observer.disconnect();},[]);
 const open=event=>{
  if(event.type==='keydown'&&!['Enter',' '].includes(event.key))return;
  const endpoint=event.target.closest?.('.ref-endpoints tbody tr');
  const incident=event.target.closest?.('.ref-incidents tbody tr');
  if(!endpoint&&!incident)return;
  const cells=(endpoint||incident).querySelectorAll('td');
  const cell=event.target.closest?.('td');
  const ip=endpoint?(cells[0]?.title||cells[0]?.textContent?.trim()):(cell===cells[4]?cells[4]?.textContent?.trim():cells[3]?.textContent?.trim());
  if(!ip||ip==='-')return;
  event.preventDefault();event.stopPropagation();
  saveFocus({ip,title:incident?(cells[2]?.title||cells[2]?.textContent?.trim()):'',created:Date.now()});
  onNavigate('incidents');
 };
 return <div ref={root} onClickCapture={open} onKeyDownCapture={open}><Original {...props} onNavigate={page=>{saveFocus(null);onNavigate(page);}}/></div>;
}
export function IncidentBridge({Original,api,initialIncidentId,...props}){
 const [focus,setFocus]=useState(readFocus),[selected,setSelected]=useState(''),[count,setCount]=useState(null),[partial,setPartial]=useState(false);
 const root=useRef(null);
 const proxy=useMemo(()=>!api||!focus?api:{...api,getIncidents:async options=>{
  const response=await api.getIncidents({...options,limit:1000});
  const all=response.items||[];
  const items=all.filter(row=>incidentHasEndpoint(row,focus.ip));
  setCount(items.length);setPartial(Number(response.total)>all.length);
  const target=items.find(row=>focus.title&&(row.title===focus.title))||items[0];
  setSelected(target?.incident_id||'');
  const summary={...response.summary,total:items.length,open:items.filter(row=>row.status==='open').length};
  for(const level of ['critical','high','medium','low']){summary[level]=items.filter(row=>row.severity===level).length;summary[`${level}_count`]=summary[level];}
  return {...response,items,total:items.length,summary};
 }},[api,focus]);
 useEffect(()=>{if(!focus||!selected||!root.current)return;let moved=false;const scroll=()=>{if(moved)return;const row=root.current.querySelector('.incident-row-selected,.row-selected,[aria-selected="true"]');if(row){row.scrollIntoView({block:'nearest'});moved=true;}};const observer=new MutationObserver(scroll);observer.observe(root.current,{subtree:true,childList:true,attributes:true,attributeFilter:['class','aria-selected']});scroll();return()=>observer.disconnect();},[focus,selected]);
 const clear=()=>{saveFocus(null);setFocus(null);setSelected('');setCount(null);};
 return <div ref={root} className="endpoint-incident-workspace">{focus&&<div className="endpoint-focus-banner" role="status"><Crosshair size={19}/><div><strong>Related incidents for <code>{focus.ip}</code></strong><small>{count===null?'Finding matching evidence...':count?`${count} related incident${count===1?'':'s'}${partial?' in loaded records':''}`:'No incidents match this IP in the current filters'}{partial?' - results may be incomplete':''}</small></div><button type="button" onClick={clear}><X size={15}/>Clear IP focus</button></div>}<Original key={focus?.created||'all'} {...props} api={proxy} initialIncidentId={focus?selected:initialIncidentId}/></div>;
}
