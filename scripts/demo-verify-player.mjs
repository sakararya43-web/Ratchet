// Verify the actual offline demo player and decode a frame in Chromium.
import {chromium} from '../web/node_modules/@playwright/test/index.mjs';
import {copyFileSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root=resolve(import.meta.dirname,'..');
const local=resolve(root,'.local/demo-ready');
copyFileSync(resolve(root,'scripts/demo-player.html'),resolve(local,'index.html'));
const browser=await chromium.launch({headless:true});
try{
  const page=await browser.newPage({viewport:{width:1440,height:1100}});
  await page.goto(pathToFileURL(resolve(local,'index.html')).href);
  const metadata=await page.locator('video').evaluate(async video=>{
    await Promise.race([
      new Promise((resolve,reject)=>{
        if(video.readyState>=1)return resolve();
        video.addEventListener('loadedmetadata',resolve,{once:true});
        video.addEventListener('error',()=>reject(new Error('Video metadata failed')),{once:true});
      }),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('Video metadata timed out')),15000)),
    ]);
    const seeked=new Promise((resolve,reject)=>{
      video.addEventListener('seeked',resolve,{once:true});
      video.addEventListener('error',()=>reject(new Error('Video decode failed')),{once:true});
      setTimeout(()=>reject(new Error('Video seek timed out')),15000);
    });
    video.currentTime=video.duration/2;await seeked;
    video.muted=true;await video.play();
    await new Promise(resolve=>video.requestVideoFrameCallback(()=>resolve()));
    video.pause();
    return {duration_seconds:video.duration,width:video.videoWidth,height:video.videoHeight,ready_state:video.readyState,error:video.error?.message??null};
  });
  const proof=JSON.parse(readFileSync(resolve(local,'recording-evidence.json'),'utf8'));
  if(metadata.error||metadata.width!==1440||metadata.height!==1000||metadata.ready_state<2||Math.abs(metadata.duration_seconds-proof.recording.duration_seconds)>1)throw new Error('Actual video does not match recording evidence');
  await page.waitForTimeout(300);
  await page.screenshot({path:resolve(local,'player-preview.png'),fullPage:true});
  writeFileSync(resolve(local,'player-evidence.json'),JSON.stringify({status:'passed',...metadata,verified_at:new Date().toISOString()},null,2)+'\n');
  console.log(JSON.stringify(metadata));
}finally{await browser.close();}
