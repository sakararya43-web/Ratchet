import { chromium, expect } from '../web/node_modules/@playwright/test/index.mjs';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
const root = resolve(import.meta.dirname, '..');
const output = resolve(root, '.local/ui-redesign');
mkdirSync(output, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({baseURL:'https://localhost:8444',viewport:{width:1440,height:1000}});
const page = await context.newPage();
const errors=[]; const requests=[];
page.on('pageerror', e=>errors.push(e.message));
page.on('request', r=>requests.push(r.url()));
await page.addInitScript(()=>{
  window.__uiMetrics={longTasks:[],lcp:0,cls:0};
  new PerformanceObserver(list=>list.getEntries().forEach(e=>window.__uiMetrics.longTasks.push(e.duration))).observe({type:'longtask',buffered:true});
  new PerformanceObserver(list=>list.getEntries().forEach(e=>window.__uiMetrics.lcp=e.startTime)).observe({type:'largest-contentful-paint',buffered:true});
  new PerformanceObserver(list=>list.getEntries().forEach(e=>{if(!e.hadRecentInput)window.__uiMetrics.cls+=e.value;})).observe({type:'layout-shift',buffered:true});
});
try {
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Power needs a boundary.'})).toBeVisible();
  await page.screenshot({path:resolve(output,'landing-desktop.png'),fullPage:true});
  const externalRequests=requests.filter(url=>!url.startsWith('https://localhost:8444/'));
  expect(externalRequests).toEqual([]);
  expect(requests.some(url=>url.includes('/api/'))).toBe(false);
  const cdp=await context.newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:4});
  const scroll=await page.evaluate(()=>new Promise(resolve=>{
    const frames=[];let last=performance.now();let n=0;
    const tick=now=>{frames.push(now-last);last=now;window.scrollTo(0,(document.documentElement.scrollHeight-innerHeight)*n/180);if(++n<=180)requestAnimationFrame(tick);else resolve(frames.slice(3));};
    requestAnimationFrame(tick);
  }));
  const frameTimes=scroll.sort((a,b)=>a-b);
  const performance=await page.evaluate(()=>({...window.__uiMetrics,resources:performance.getEntriesByType('resource').map(r=>({name:new URL(r.name).pathname,bytes:r.transferSize}))}));
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:1});
  await page.getByRole('button',{name:/One person cannot become a quorum/}).click();
  await expect(page.locator('#evidence-1')).toBeVisible();
  await page.getByRole('button',{name:/Trust the outcome/}).click();
  await expect(page.locator('#protocol-display')).toContainText('TARGET VERIFICATION');
  await page.locator('#chapter-1').scrollIntoViewIfNeeded();
  await page.screenshot({path:resolve(output,'protocol-desktop.png')});
  const sizes=[];
  for(const width of [360,390,768,1440]){
    await page.setViewportSize({width,height:844});await page.goto('/');
    await expect(page.locator('.hero')).toBeVisible();
    const fits=await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth);
    expect(fits,`Landing fits ${width}px`).toBe(true);sizes.push(width);
    if(width===390) await page.screenshot({path:resolve(output,'landing-mobile.png'),fullPage:true});
  }
  await page.goto('/#/console');
  await expect(page.getByLabel('Tenant',{exact:true})).toBeVisible();
  await page.screenshot({path:resolve(output,'login-desktop.png'),fullPage:true});
  const accounts=JSON.parse(readFileSync(resolve(root,'.local/prototype/users.json'),'utf8'));
  const account=accounts.users.find(u=>u.actor_id==='user:finance-lead');
  await page.getByLabel('Tenant',{exact:true}).fill(accounts.tenant_id);
  await page.getByLabel('Actor',{exact:true}).fill(account.actor_id);
  await page.getByLabel('Password',{exact:true}).fill(account.password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.getByTestId('signed-in-actor')).toContainText(account.actor_id);
  await expect(page.getByRole('button',{name:'Refresh',exact:true})).toBeEnabled();
  await page.screenshot({path:resolve(output,'console-desktop.png'),fullPage:true});
  const tabs=['Overview','Changes','Infrastructure','Impact','Security policy','Incidents','Audit','Passkeys'];
  for(const tab of tabs){
    await page.getByRole('navigation',{name:'Console',exact:true}).getByRole('button',{name:tab,exact:true}).click();
    await expect(page.getByRole('button',{name:'Refresh',exact:true})).toBeEnabled();
    await expect(page.getByRole('heading',{name:tab,exact:true})).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
    if(tab==='Infrastructure'){
      const count=await page.locator('tbody tr').count();expect(count).toBeGreaterThan(0);
      await page.getByLabel('Find an observed node').fill('not-a-real-resource');
      await expect(page.locator('tbody tr')).toHaveCount(0);
      await page.getByLabel('Find an observed node').clear();
      await expect(page.locator('tbody tr')).toHaveCount(count);
    }
    if(['Changes','Infrastructure','Passkeys','Audit'].includes(tab)) await page.screenshot({path:resolve(output,`${tab.toLowerCase()}-desktop.png`)});
    await page.setViewportSize({width:390,height:844});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${tab} fits mobile`).toBe(true);
    if(tab==='Overview') await page.screenshot({path:resolve(output,'console-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
  }
  await page.getByRole('link',{name:'Back to website'}).click();
  await page.getByRole('link',{name:'Enter the console',exact:true}).click();
  await expect(page.getByTestId('signed-in-actor')).toContainText(account.actor_id);
  await page.emulateMedia({reducedMotion:'reduce'});await page.goto('/');
  expect(await page.locator('.scroll-wheel > span').evaluate(el=>getComputedStyle(el).animationName)).toBe('none');
  await page.keyboard.press('Tab');await page.keyboard.press('Enter');
  await expect(page.locator('#landing-content')).toBeFocused();
  expect(errors).toEqual([]);
  const report={completed_at:new Date().toISOString(),tested_widths:sizes,console_tabs:tabs,errors,external_requests:externalRequests,performance:{...performance,scroll_cpu_throttle:4,scroll_frames:frameTimes.length,frame_median_ms:frameTimes[Math.floor(frameTimes.length*.5)],frame_p95_ms:frameTimes[Math.floor(frameTimes.length*.95)],frames_over_50ms:frameTimes.filter(n=>n>50).length},notes:'Local Chromium measurements on this machine, not a guarantee for all devices. Uses real authenticated read-only console APIs; full approval acceptance is run separately.'};
  writeFileSync(resolve(output,'ui-verification.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report,null,2));
} finally {await browser.close();}
