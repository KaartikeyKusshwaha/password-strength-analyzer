import {useEffect,useRef,useState} from 'react';
import {api} from './api';

export const emptyDependency=()=>({content:'',format:'requirements',dependency_selection:null,dependency_consent:false});
export const dependencyReady=value=>value.dependency_consent&&value.dependency_selection?.length>0;

export function DependencyCoverage({coverage}) {
  if(!coverage)return null;
  return <div className="notice"><strong>Dependency inventory coverage</strong><p>{coverage.selected} selected / {coverage.unique_packages} unique package versions · {coverage.excluded} excluded · {coverage.skipped_records} unsupported records · {coverage.root_records} project roots · {coverage.duplicate_records} duplicate records</p>{Object.entries(coverage.skipped_reasons||{}).map(([reason,count])=><p className="fine" key={reason}>{count} · {reason}</p>)}<p className="fine">Locked dev, optional and platform variants are included when present. This is not a list of software installed on your device or proof of exploitability.</p></div>;
}

export default function DependencyScope({value,onChange,disabled=false,consentText}) {
  const [scope,setScope]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[expanded,setExpanded]=useState(false);
  const generation=useRef(0);
  const lastSource=useRef({content:value.content,format:value.format});
  useEffect(()=>()=>{generation.current++;},[]);
  useEffect(()=>{
    if(lastSource.current.content!==value.content||lastSource.current.format!==value.format){
      generation.current++;setScope(null);setBusy(false);setError('');setExpanded(false);
      lastSource.current={content:value.content,format:value.format};
    }
  },[value.content,value.format]);
  function source(change) {
    generation.current++;setScope(null);setError('');setBusy(false);setExpanded(false);
    lastSource.current={content:value.content,format:value.format,...change};
    onChange({...value,...change,dependency_selection:null,dependency_consent:false});
  }
  async function load(event) {
    const file=event.target.files?.[0];event.target.value='';if(!file)return;
    const ticket=++generation.current;setScope(null);setBusy(true);setError('');
    onChange({...value,dependency_selection:null,dependency_consent:false});
    try {
      if(file.size>1048576)throw new Error('Choose a dependency file up to 1 MiB.');
      const text=await file.text();if(ticket!==generation.current)return;
      const name=file.name.toLowerCase(),format=name==='uv.lock'?'uv-lock':['package-lock.json','npm-shrinkwrap.json'].includes(name)?'package-lock':name==='package.json'?'package-json':'requirements';
      source({content:text,format});
    }catch(error){if(ticket===generation.current)setError(error.message);}
    finally{if(ticket===generation.current)setBusy(false);}
  }
  async function inspect() {
    const ticket=++generation.current;setBusy(true);setError('');setScope(null);
    onChange({...value,dependency_selection:null,dependency_consent:false});
    try {
      const result=await api('/dependency-inventory/preview',{content:value.content,format:value.format});
      if(ticket!==generation.current)return;
      setScope(result);onChange({...value,dependency_selection:result.packages.map(p=>p.id),dependency_consent:false});
    }catch(error){if(ticket===generation.current)setError(error.message);}
    finally{if(ticket===generation.current)setBusy(false);}
  }
  function select(ids){onChange({...value,dependency_selection:ids,dependency_consent:false});}
  const selected=value.dependency_selection||[],pins=scope?.packages||[];
  return <fieldset disabled={disabled}>
    <label>Dependency format<select value={value.format} onChange={e=>source({format:e.target.value})}><option value="requirements">requirements.txt · exact pins</option><option value="package-json">package.json · exact pins</option><option value="package-lock">package-lock.json · v2/v3</option><option value="uv-lock">uv.lock · v1</option><option value="exact-inventory">Registered exact inventory</option></select></label>
    <label>Import dependency file<input type="file" accept=".txt,.json,.lock" onChange={load}/></label>
    <label>Dependency source<textarea value={value.content} onChange={e=>source({content:e.target.value})} rows={5} spellCheck={false} maxLength={1048576}/></label>
    <p className="fine">Up to 500 exact package versions and 1 MiB of source. Preview processes this text on your SentinelOps backend without contacting OSV. Raw lockfiles, paths and URLs are not stored. Standard registry URLs do not prove package names are public.</p>
    <button type="button" className="button secondary" disabled={busy||!value.content.trim()} onClick={inspect}>{busy?'Reading inventory…':'Preview package scope'}</button>
    {error&&<p role="alert" className="notice error">{error}</p>}
    {scope&&<><DependencyCoverage coverage={{...scope.coverage,selected:selected.length,excluded:pins.length-selected.length}}/>
      <p>Exclude private package names before approving an external query.</p>
      <button type="button" className="text-button" onClick={()=>select(pins.map(p=>p.id))}>Select all parsed versions</button>{' '}
      <button type="button" className="text-button" onClick={()=>select([])}>Clear selection</button>
      {(expanded?pins:pins.slice(0,30)).map(p=><label className="check" key={p.id}><input type="checkbox" checked={selected.includes(p.id)} onChange={e=>select(e.target.checked?[...selected,p.id]:selected.filter(id=>id!==p.id))}/>{p.ecosystem} · {p.name}@{p.version}</label>)}
      {pins.length>30&&<button type="button" className="text-button" onClick={()=>setExpanded(!expanded)}>{expanded?'Show first 30 versions':`Show all ${pins.length} versions`}</button>}
      <label className="check"><input type="checkbox" checked={value.dependency_consent} disabled={!selected.length||busy} onChange={e=>onChange({...value,dependency_consent:e.target.checked})}/>{consentText||'I approve sending the selected package names and versions to OSV for vulnerability checks.'}</label>
      <p className="fine">Changing the source or selection clears approval. Unsupported records and excluded versions remain coverage gaps. No installers or submitted URLs are executed.</p>
    </>}
  </fieldset>;
}
