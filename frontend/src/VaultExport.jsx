import {useState} from 'react';
import {downloadCredentialCsv,exportableLogins} from './credential-export';

export default function VaultExport({entries,disabled=false}) {
  const [includeArchived,setIncludeArchived]=useState(false),[approval,setApproval]=useState(null),[notice,setNotice]=useState(''),[error,setError]=useState('');
  const logins=exportableLogins(entries,includeArchived);
  // Tie approval to this exact set of values, not merely a count. No plaintext leaves memory here.
  const approved=approval===entries;
  return <details className="panel"><summary>Move logins to another password manager</summary>
    <h2>Export login CSV</h2><p>Download this personal vault’s login names, website origins, usernames and current saved passwords in Chrome-compatible CSV format. Only this unlocked vault is included. No data is sent to the server or AI.</p>
    <p className="notice">This file is unencrypted and contains passwords. Import it directly into your destination password manager, keep it private, then remove it when no longer needed. Do not open it in a spreadsheet: exact credential values may be interpreted as formulas.</p>
    <p className="fine">Authenticator keys, notes, history, pending password proposals, sharing keys and vault settings are excluded. A saved password is not proof that a website accepts it. Use an encrypted backup to preserve all vault contents.</p>
    <label className="check"><input type="checkbox" checked={includeArchived} disabled={disabled} onChange={event=>{setIncludeArchived(event.target.checked);setApproval(null);setNotice('');}}/>Include archived login entries</label>
    <p>{logins.length} login entries selected for export.</p>
    <label className="check"><input type="checkbox" checked={approved} disabled={disabled||!logins.length} onChange={event=>{setApproval(event.target.checked?entries:null);setNotice('');}}/>I understand this downloads plaintext passwords for the selected entries.</label>
    <button className="button secondary" disabled={disabled||!approved||!logins.length} onClick={()=>{setError('');try{downloadCredentialCsv(entries,includeArchived);setApproval(null);setNotice('CSV download requested. Verify the file saved before importing it elsewhere.');}catch(error){setError(error.message);}}}>Download plaintext login CSV</button>
    {notice&&<p role="status">{notice}</p>}{error&&<p role="alert">{error}</p>}
  </details>;
}
