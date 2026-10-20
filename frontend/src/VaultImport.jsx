import { useState } from 'react';
import { importCredentials } from './credential-import';
export default function VaultImport({ onImport, disabled, existingCount }) {
  const [preview,setPreview]=useState(null),[error,setError]=useState('');
  return <section className="panel"><h2>Bring your existing accounts</h2><p className="muted">Import Chrome, Bitwarden, 1Password or LastPass CSV exports. Parsing and encryption happen locally; the CSV and plaintext credentials never go to the server or AI.</p><p className="fine">CSV export files contain plaintext passwords. Keep the file private and remove it securely when you no longer need it. Only HTTPS logins and supported TOTP keys are imported; other item types are listed as skipped. Notes, attachments and custom fields are not imported.</p>
    {error && <p className="notice error" role="alert">{error}</p>}
    {!preview ? <label>Credential CSV<input type="file" accept=".csv,text/csv" disabled={disabled} onChange={async event=>{setError('');const file=event.target.files[0];event.target.value='';if(!file)return;try{if(file.size>2000000)throw new Error('Choose a CSV under 2 MB.');setPreview(importCredentials(await file.text()));}catch(error){setError(error.message);}}}/></label> : <>
      <h3>{preview.format} import preview</h3><p>{preview.entries.filter(e=>e.type==='login').length} logins · {preview.entries.filter(e=>e.type==='totp').length} authenticator entries · {preview.skipped.length} skipped records or fields.</p>
      <ul>{preview.entries.filter(e=>e.type==='login').slice(0,8).map(entry=><li key={entry.id}>{entry.title} · {entry.origin} · {entry.username}</li>)}</ul>
      {!!preview.skipped.length && <details><summary>Skipped records and reasons</summary><ul>{preview.skipped.slice(0,30).map((item,index)=><li key={index}>Row {item.row}: {item.reason}</li>)}</ul></details>}
      {existingCount+preview.entries.length>200 && <p className="notice error">This vault’s current limit is 200 entries. Split the import into separate vaults before continuing.</p>}
      <button className="button" disabled={disabled || existingCount+preview.entries.length>200} onClick={async()=>{setError('');try{if(await onImport(preview.entries))setPreview(null);}catch(error){setError(error.message);}}}>Encrypt and import into this vault</button><button className="button secondary" onClick={()=>setPreview(null)}>Discard preview</button>
    </>}
  </section>;
}
