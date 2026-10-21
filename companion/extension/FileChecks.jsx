import React,{useRef,useState} from 'react';
import {securityRequest} from './security-client';

export const FILE_LIMIT=65536;
export default function FileChecks({connection,running,ai,onQueued}){
  const [kind,setKind]=useState('python'),[format,setFormat]=useState('requirements'),[content,setContent]=useState(''),[inventory,setInventory]=useState(null),[selected,setSelected]=useState([]),[consent,setConsent]=useState(false),[disclosure,setDisclosure]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const generation=useRef(0);
  function invalidate(){generation.current++;setInventory(null);setSelected([]);setConsent(false);setDisclosure(false);setError('');}
  function change(value){invalidate();setContent(value);}
  async function fileInput(file){
    if(!file)return;
    invalidate();const current=generation.current;
    try{
      if(file.size>FILE_LIMIT)throw new Error('Use one UTF-8 text file up to 64 KiB.');
      const value=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      if(current!==generation.current)return;
      if(value.includes('\0'))throw new Error('Binary files are not supported.');
      setContent(value);
    }catch(e){if(current===generation.current){setContent('');setError(e.message);}}
  }
  const valid=Boolean(content.trim())&&new TextEncoder().encode(content).length<=FILE_LIMIT;
  async function preview(){
    setBusy(true);setError('');const current=generation.current;
    try{
      const value=await securityRequest(connection,'/inventory-preview',{content,format});
      if(current===generation.current){setInventory(value);setSelected([]);setConsent(false);}
    }catch(e){if(current===generation.current)setError(e.message);}finally{setBusy(false);}
  }
  async function run(){
    setBusy(true);setError('');
    try{
      const body={action:kind,authorized:true,ai_triage:ai,content,target:kind==='python'?'Submitted Python':'Submitted dependencies',device_id:'local',...(kind==='dependencies'?{format,dependency_selection:selected,dependency_consent:consent}:{})};
      const operation=await securityRequest(connection,'/operations',body);
      await onQueued(operation);change('');
    }catch(e){setError(e.message);}finally{setBusy(false);}
  }
  return <details><summary>Advanced · check code or dependencies</summary>
    <p>Runs in cloud. Read-only checks; files are never executed. Paste or drop one UTF-8 text file up to 64 KiB. Remove passwords, keys and confidential data first. Submitted text stays in this popup until you send it; it is not saved in extension storage.</p>
    <label>File check<select disabled={running||busy} value={kind} onChange={event=>{invalidate();setKind(event.target.value);}}><option value="python">Python source patterns</option><option value="dependencies">Dependency advisories</option></select></label>
    {kind==='dependencies'&&<label>Dependency format<select disabled={running||busy} value={format} onChange={event=>{invalidate();setFormat(event.target.value);}}><option value="requirements">requirements.txt</option><option value="package-json">package.json</option><option value="package-lock">package-lock.json v2/v3</option><option value="uv-lock">uv.lock</option><option value="exact-inventory">Exact package inventory</option></select></label>}
    <label>Choose text file<input type="file" disabled={running||busy} accept=".py,.txt,.json,.lock,.toml" onChange={event=>{fileInput(event.target.files?.[0]);event.target.value='';}}/></label>
    <label>Paste or drop file contents<textarea rows="6" disabled={running||busy} value={content} onChange={event=>change(event.target.value)} onDragOver={event=>event.preventDefault()} onDrop={event=>{event.preventDefault();if(!running&&!busy)fileInput(event.dataTransfer.files?.[0]);}}/></label>
    {!valid&&content&&<p className="error">Use non-empty text up to 64 KiB.</p>}
    <label><input type="checkbox" disabled={running||busy} checked={disclosure} onChange={event=>setDisclosure(event.target.checked)}/>I can assess this file and approve sending its contents to my connected SentinelOps service.</label>
    {kind==='dependencies'&&<><button className="secondary" disabled={running||busy||!valid||!disclosure} onClick={preview}>{busy?'Preparing inventory…':'Preview exact packages'}</button>
      {inventory&&<><p>{inventory.packages.length} exact package/version pairs found. Select the public packages to check. Exclude private names.</p><div className="inventory-list">{inventory.packages.map(item=><label key={item.id}><input type="checkbox" disabled={running||busy} checked={selected.includes(item.id)} onChange={event=>{setSelected(event.target.checked?[...selected,item.id]:selected.filter(id=>id!==item.id));setConsent(false);}}/>{item.ecosystem} · {item.name}@{item.version}</label>)}</div>{inventory.skipped?.length>0&&<details><summary>Skipped records and coverage</summary>{inventory.skipped.map((item,index)=><p key={index}>{item}</p>)}<p>{inventory.limits}</p></details>}
      <label><input type="checkbox" disabled={running||busy||!selected.length} checked={consent} onChange={event=>setConsent(event.target.checked)}/>Send only the {selected.length} selected package names and exact versions to OSV for public advisory lookup.</label></>}
    </>}
    <p className="fine">{kind==='python'?'Static patterns only; no execution, whole-project analysis or proof of exploitability.':'Exact pins only; missing, skipped or unavailable advisory results do not certify safety.'} {ai?'AI prioritization is enabled above; observations may be sent for action drafts.':'AI prioritization is off.'}</p>
    <button disabled={running||busy||!valid||!disclosure||(kind==='dependencies'&&(!inventory||!selected.length||!consent))} onClick={run}>{busy?'Starting check…':kind==='python'?'Approve and check Python':'Approve and check selected packages'}</button>
    {error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
