import {expect,it} from 'vitest';
import {readRoute,pageRoute} from './navigation';
const location=(pathname,hash='')=>({pathname,hash});
it('requires both the advanced path and runtime flag for legacy tools',()=>{
  expect(readRoute(location('/advanced','#page=scans'),true)).toEqual({advanced:true,page:'scans'});
  expect(readRoute(location('/advanced','#page=scans'),false)).toEqual({advanced:false,page:'vault'});
  expect(readRoute(location('/','#page=scans'),true).page).toBe('vault');
  expect(pageRoute('scans',false).url).toBe('/');
  expect(pageRoute('scans',true).url).toBe('/advanced#page=scans');
});
it('restores control room history without enabling legacy panels and rejects unknown pages',()=>{
  const route=pageRoute('workflows',false),url=new URL(route.url,'https://app.example.test');
  expect(readRoute(url,false)).toEqual({advanced:false,page:'workflows'});
  expect(readRoute(location('/advanced','#page=not-a-page'),true).page).toBe('overview');
  expect(pageRoute('not-a-page',true).page).toBe('vault');
});
