import {_electron} from 'playwright';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const python=process.env.NETBOT_SMOKE_PYTHON_BIN;
const bundle=process.env.NETBOT_SMOKE_BACKEND_DIR||path.join(repo,'.runtime/security-build/dist/netbotpro-backend');
const binary=path.join(bundle,process.platform==='win32'?'netbotpro-backend.exe':'netbotpro-backend');
await fs.access(python||binary);
const listener=net.createServer();
await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
const port=listener.address().port;
await new Promise(resolve=>listener.close(resolve));
const electron=path.join(repo,'desktop/electron/node_modules/electron',process.platform==='win32'?'dist/electron.exe':'dist/electron');
const temporary=path.resolve(os.tmpdir());
const profile=await fs.mkdtemp(path.join(temporary,'netbot-electron-smoke-'));
let app;
try{
 const env={...process.env,NETBOT_SMOKE_USER_DATA:profile,NETBOT_PORT:String(port),NETBOT_DISABLE_GPU:'1',
  NETBOT_DB_PATH:path.join(profile,'history.db'),NETBOT_FLOW_DB_PATH:path.join(profile,'flows.db'),
  NETBOT_CAPTURE_JOURNAL_PATH:path.join(profile,'journal.db'),NETBOT_CACHE_DIR:path.join(profile,'cache'),
  NETBOT_RUNTIME_DIR:path.join(profile,'runtime'),NETBOT_STABILITY_RECORDING:'0'};
 if(python){delete env.NETBOT_BACKEND_BIN;env.NETBOT_PYTHON_BIN=python;}else{env.NETBOT_BACKEND_BIN=binary;}
 app=await _electron.launch({executablePath:electron,args:[path.join(repo,'scripts/qa/electron_runtime_bootstrap.cjs')],env,timeout:45000});
 const window=await app.firstWindow();
 const errors=[];window.on('pageerror',error=>errors.push(error.message));
 await window.locator('nav.app-nav').waitFor({timeout:45000});
 assert.match(await window.locator('body').innerText(),/NetBotPro/i);
 const bridge=await window.evaluate(()=>({present:!!window.netbotproDesktop,rendererNode:typeof window.require}));
 assert.equal(bridge.present,true);assert.equal(bridge.rendererNode,'undefined');
 const runtime=await app.evaluate(({BrowserWindow})=>{
  const prefs=BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();
  return {electron:process.versions.electron,sandbox:prefs.sandbox,contextIsolation:prefs.contextIsolation,nodeIntegration:prefs.nodeIntegration};
 });
 assert.equal(runtime.sandbox,true);assert.equal(runtime.contextIsolation,true);assert.equal(runtime.nodeIntegration,false);
 const response=await fetch(`http://127.0.0.1:${port}/api/health`);
 assert.equal(response.ok,true);
 if(process.env.NETBOT_DESKTOP_UI==='desktop'){
  await window.getByRole('heading',{name:'Command Center',exact:true}).waitFor();
  // This smoke window is deliberately hidden. Browser fixtures test pointer actionability.
  await window.locator('nav.app-nav').getByRole('button',{name:'Live Monitor',exact:true}).dispatchEvent('click');
  await window.getByRole('heading',{name:'Live Monitor',exact:true}).waitFor();
  await window.locator('nav.app-nav').getByRole('button',{name:'Fleet',exact:true}).dispatchEvent('click');
  await window.getByRole('heading',{name:'Fleet',exact:true}).waitFor();
 }
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({runtime,rendererBridge:true,backendHealth:true,sourceBackend:!!python,entry:process.env.NETBOT_DESKTOP_UI||'standard'}));
 await app.close();app=null;
 const log=await fs.readFile(path.join(profile,'logs/desktop-backend.log'),'utf8');
 assert.match(log,/capture and history drain confirmed/);
 console.log('Electron renderer, isolated IPC bridge, backend startup and normal drain passed.');
}finally{
 try{await app?.close();}finally{
  const resolved=path.resolve(profile);
  if(path.dirname(resolved)!==temporary||!path.basename(resolved).startsWith('netbot-electron-smoke-'))throw Error('Unexpected smoke workspace');
  await fs.rm(resolved,{recursive:true,force:true,maxRetries:10,retryDelay:100});
 }
}
