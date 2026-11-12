const number = value => value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
const first = (...values) => values.map(number).find(v => v !== null) ?? null;
export function pressureLabel(value) {
 if(value === null) return '-';
 if(value > 0 && value < 0.1) return '<0.1%';
 return `${Number(value.toFixed(1))}%`;
}
export function queueSnapshot(metrics = {}) {
 const rows=[];
 function add(name, source, fields={}) {
  if(!source || source.enabled === false) return;
  const depth=first(source[fields.depth],source.current_depth,source.queue_depth_total,source.queue_depth,source.queue_size,source.depth);
  const capacity=first(source[fields.capacity],source.max_size,source.queue_max_total,source.queue_max,source.client_queue_max,source.capacity);
  const percent=depth !== null && capacity > 0 ? 100*depth/capacity : first(source.utilization_percent,source.queue_utilization_percent);
  const peakDepth=first(source.high_water_mark,source.queue_high_water_mark);
  const peak=peakDepth !== null && capacity > 0 ? 100*peakDepth/capacity : null;
  const dropped=first(source.dropped_total,source.jobs_dropped_total,source.dropped_packets,source.dropped_for_slow_client_total);
  const failed=first(source.failed_total,source.jobs_failed_total,source.send_errors_total);
  const health=source.health || (source.worker_alive === false?'critical':failed>0 || dropped>0?'degraded':percent===null?'unavailable':percent>=95?'critical':percent>=70?'warning':'healthy');
  rows.push({name,depth,capacity,percent,peak,dropped,failed,health});
 }
 add('Packet intake',metrics.packet_queue);
 add('Flow workers',metrics.flow_worker_pool);
 add('Persistence',metrics.persistence);
 add('WebSocket clients',metrics.websocket || metrics.event_bus,{depth:'client_queue_depth_max'});
 const valid=rows.map(row=>row.percent).filter(v=>v!==null);
 const pressure=valid.length?Math.max(...valid):first(metrics.queue_pressure);
 const degraded=rows.some(row=>/critical|degraded|warning|failed|error/.test(row.health));
 return {rows,pressure,label:pressureLabel(pressure),health:pressure===null?'Metrics unavailable':degraded?'Degraded':pressure>=70?'Under pressure':'Normal'};
}
