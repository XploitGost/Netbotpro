import {build} from 'esbuild';
import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.dirname(fileURLToPath(import.meta.url));
const repo=path.resolve(root,'../..');
const output=path.join(repo,'.runtime/docs-preview');
await fs.mkdir(output,{recursive:true});
await build({entryPoints:[path.join(root,'docs-preview.jsx')],bundle:true,outfile:path.join(output,'preview.js'),minify:false,
  alias:{react:path.join(root,'node_modules/react')},loader:{'.png':'dataurl'}});
const shell=`body{margin:0;background:#06141e}body:before{display:none}.docs-shell{width:100%;margin:0;padding:0;--topbar-height:56px}.docs-shell>.app-nav{position:fixed;left:0;top:0;width:206px;height:100vh;margin:0}.docs-shell>.soc-topbar{position:fixed;left:206px;right:0;top:0;height:56px;z-index:10}.docs-shell>.soc-main{margin-left:206px;padding:64px 10px 8px;min-height:100vh;box-sizing:border-box}.workspace-header{padding:6px 14px}.workspace-header h1{margin:0;font-size:30px}.workspace-header p{margin:3px 0 10px}.docs-shell .ff-layout{height:calc(100vh - 74px)}*{letter-spacing:0!important}`;
const html=`<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/preview.css"><style>${shell}</style></head><body><div id="root"></div><script src="/preview.js"></script></body></html>`;
const server=http.createServer(async(req,res)=>{
  const name=new URL(req.url,'http://localhost').pathname;
  if(name==='/' ){res.setHeader('Content-Type','text/html');res.end(html);return;}
  if(!['/preview.js','/preview.css'].includes(name)){res.writeHead(404).end();return;}
  res.setHeader('Content-Type',name.endsWith('.css')?'text/css':'text/javascript');
  res.end(await fs.readFile(path.join(output,name.slice(1))));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,...(process.env.NETBOT_CHROME_PATH?{executablePath:process.env.NETBOT_CHROME_PATH}:{})});
  const page=await browser.newPage({viewport:{width:1672,height:941},deviceScaleFactor:1,timezoneId:'UTC'});
  await page.clock.setFixedTime(new Date('2026-11-09T12:00:00Z'));
  const errors=[];page.on('pageerror',e=>errors.push(e.stack||e.message));
  await page.route('**/*',route=>new URL(route.request().url()).hostname==='127.0.0.1'?route.continue():route.abort());
  for(const [view,name] of [['command','overview'],['monitor','monitor'],['inspect','inspect'],['agents','fleet']]){
    await page.goto(`http://127.0.0.1:${server.address().port}/?page=${view}`,{waitUntil:'networkidle'});
    if(errors.length)throw Error(errors.join('\n'));
    await page.locator('main h1, main h2').first().waitFor();
    await page.screenshot({path:path.join(repo,`docs/assets/netbotpro-${name}.png`)});
    if(errors.length)throw Error(errors.join('\n'));
    console.log(`Captured synthetic ${view} preview`);
  }
}finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
