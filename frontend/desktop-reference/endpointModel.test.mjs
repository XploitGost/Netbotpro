import assert from 'node:assert/strict';
import {endpointRiskSnapshot} from './dashboardModel.js';
assert.equal(endpointRiskSnapshot({}).available,false);
const summary={endpoint_risk:{scope:'detector_events',coverage_complete:true,items:[
 {ip:'busy',count:999,risk:'low',trend:[1,0,0,2,0]},
 {ip:'rare',count:1,risk:'critical',trend:[null,null,0,1,-1]},
]}};
const before=JSON.stringify(summary),result=endpointRiskSnapshot(summary);
assert.equal(result.items[0].ip,'rare');
assert.deepEqual(result.items[0].trend,[null,null,0,1,null]);
assert.equal(result.items[1].count,999);
assert.equal(JSON.stringify(summary),before);
assert.equal(endpointRiskSnapshot({endpoint_risk:{scope:'detector_events',items:[]}}).available,true);
assert.equal(endpointRiskSnapshot({endpoint_risk:{scope:'detector_events',coverage_complete:false,items:[]}}).coverage_complete,false);
console.log('Endpoint model: measured source, risk priority, missing/zero buckets, immutable data and explicit incomplete coverage passed.');
