import {_electron} from 'playwright';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const bundle=process.env.NETBOT_SMOKE_BACKEND_DIR||path.join(repo,'.runtime/security-build/dist/netbotpro-backend');
const binary=path.join(bundle,process.platform==='win32'?'netbotpro-backend.exe':'netbotpro-backend');
await fs.access(binary);
const listener=net.createServer();
await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
const port=listener.address().port;
await new Promise(resolve=>listener.close(resolve));
const electron=path.join(repo,'desktop/electron/node_modules/electron',process.platform==='win32'?'dist/electron.exe':'dist/electron');
const profile=path.join(repo,'.runtime/security-electron-profile');
const app=await _electron.launch({executablePath:electron,args:[path.join(repo,'scripts/qa/electron_runtime_bootstrap.cjs')],
  env:{...process.env,NETBOT_SMOKE_USER_DATA:profile,NETBOT_PORT:String(port),NETBOT_BACKEND_BIN:binary,NETBOT_DISABLE_GPU:'1'},timeout:45000});
try{
  const window=await app.firstWindow();
  await window.locator('nav.app-nav').waitFor({timeout:45000});
  assert.match(await window.locator('body').innerText(),/NetBotPro/i);
  const bridge=await window.evaluate(()=>({present:!!window.netbotproDesktop,rendererNode:typeof window.require}));
  assert.equal(bridge.present,true);
  assert.equal(bridge.rendererNode,'undefined');
  const runtime=await app.evaluate(({BrowserWindow})=>{
    const prefs=BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();
    return {electron:process.versions.electron,sandbox:prefs.sandbox,contextIsolation:prefs.contextIsolation,nodeIntegration:prefs.nodeIntegration};
  });
  assert.equal(runtime.sandbox,true);assert.equal(runtime.contextIsolation,true);assert.equal(runtime.nodeIntegration,false);
  const response=await fetch(`http://127.0.0.1:${port}/api/health`);
  assert.equal(response.ok,true);
  console.log(JSON.stringify({runtime,rendererBridge:true,backendHealth:true}));
}finally{await app.close();}
const log=await fs.readFile(path.join(profile,'logs/desktop-backend.log'),'utf8');
assert.match(log,/capture and history drain confirmed/);
console.log('Electron renderer, isolated IPC bridge, backend startup and normal drain passed.');
