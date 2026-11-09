export const BUCKET_MS=2000;
const buckets=new Map();
const seen=new Map();
let lastPrune=0;
export function resetTraffic(){buckets.clear();seen.clear();lastPrune=0;}
export function packetTime(packet,now=Date.now()){
 const value=packet.ts??packet.timestamp??packet.time;
 if(typeof value==='number')return value<1e12?value*1000:value;
 const parsed=Date.parse(value);if(Number.isFinite(parsed))return parsed;
 const clock=/^(\d{2}):(\d{2}):(\d{2})$/.exec(String(value||''));
 if(clock){const date=new Date(now);date.setHours(+clock[1],+clock[2],+clock[3],0);if(date.getTime()>now+60000)date.setDate(date.getDate()-1);return date.getTime();}
 return now;
}
export function recordPacket(packet,now=Date.now()){
 const at=packetTime(packet,now);if(at<now-3600000||at>now+1000)return;
 const id=packet.id??packet.packet_id??JSON.stringify([packet.ts??packet.timestamp??packet.time,packet.src,packet.dst,packet.sport,packet.dport,packet.length,packet.summary]);
 if(seen.has(id))return;seen.set(id,at);
 const stamp=Math.floor(at/BUCKET_MS)*BUCKET_MS;
 const bucket=buckets.get(stamp)||{time:stamp,packets:0,inboundBytes:0,outboundBytes:0,suspiciousBytes:0,maliciousBytes:0};
 const bytes=Math.max(0,Number(packet.length??packet.len??packet.size??packet.bytes??0)||0);
 const direction=String(packet.direction||packet.traffic_direction||'').toLowerCase();
 if(['incoming','inbound'].includes(direction))bucket.inboundBytes+=bytes;
 if(['outgoing','outbound'].includes(direction))bucket.outboundBytes+=bytes;
 const risk=String(packet.severity||packet.risk_level||'').toLowerCase();
 if(risk==='critical'||packet.malicious===true)bucket.maliciousBytes+=bytes;
 else if(packet.is_alert||['medium','high'].includes(risk))bucket.suspiciousBytes+=bytes;
 bucket.packets++;buckets.set(stamp,bucket);
 if(now-lastPrune>=1000){for(const [key,value] of seen)if(value<now-3600000)seen.delete(key);for(const key of buckets.keys())if(key<now-3600000)buckets.delete(key);lastPrune=now;}
 while(seen.size>100000)seen.delete(seen.keys().next().value);
}
export function trafficPoints(now=Date.now()){
 const end=Math.floor(now/BUCKET_MS)*BUCKET_MS;
 return [...buckets.values()].filter(b=>b.time<end&&b.time>=now-3600000).sort((a,b)=>a.time-b.time).map(b=>({time:b.time+BUCKET_MS/2,packets:b.packets,...Object.fromEntries(['inbound','outbound','suspicious','malicious'].map(k=>[k,b[`${k}Bytes`]*8/(BUCKET_MS/1000)/1e6]))}));
}
export function trafficRates(now=Date.now()){
 const stamp=Math.floor(now/BUCKET_MS)*BUCKET_MS-BUCKET_MS;
 const b=buckets.get(stamp);
 return {inbound_bps:(b?.inboundBytes||0)*8/(BUCKET_MS/1000),outbound_bps:(b?.outboundBytes||0)*8/(BUCKET_MS/1000),packets_per_second:(b?.packets||0)/(BUCKET_MS/1000)};
}
export function hoverSample(points,stamp){
 if(!points.length)return null;
 const p=points.reduce((a,b)=>Math.abs(b.time-stamp)<Math.abs(a.time-stamp)?b:a);
 return Math.abs(p.time-stamp)<=BUCKET_MS/2?p:null;
}
