import {it,expect,vi} from 'vitest';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {waitFor} from '@testing-library/react';
it('opens only the fragment capability, clears the address and renders hostile metadata as text',async()=>{
 document.body.innerHTML='<p id="status"></p><p id="brand"></p><div id="controls" hidden></div><article id="report"></article><button id="pdf"></button><button id="json"></button>';
 const id='a'.repeat(24),token='x'.repeat(54);history.replaceState(null,'','/proof#'+id+':'+token);
 const data={id,brand:'<img src=x onerror=alert(1)>',client:{name:'Fixture client'},generated_at:'2026-10-23',digest:'d'.repeat(64),limitations:'Point-in-time records.',people:[],vaults:[],access:[],reported_accounts:[],offboarding:[],steps:[],rechecks:[],debt:[],handoffs:[],checks:[],posture:[],posture_included:false,audit:{valid:true,head:'h'.repeat(64),events:[]}};
 const fetcher=vi.fn(async()=>({ok:true,json:async()=>data}));vi.stubGlobal('fetch',fetcher);
 const script=readFileSync(resolve(process.cwd(),'../backend/public/proof-view.js'),'utf8');new Function(script)();
 await waitFor(()=>expect(document.getElementById('status').textContent).toContain('Fixture client'));
 expect(location.hash).toBe('');expect(document.getElementById('brand').textContent).toBe(data.brand);expect(document.querySelector('img')).toBeNull();
 expect(fetcher).toHaveBeenCalledWith('/api/public/proof-pack',expect.objectContaining({credentials:'omit',redirect:'error',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({id,format:'json'})}));
 history.replaceState(null,'','/');
});
