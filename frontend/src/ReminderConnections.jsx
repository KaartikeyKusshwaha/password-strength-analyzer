import React,{useState} from 'react';
import {api} from './api';
export default function ReminderConnections(){
 const [busy,setBusy]=useState(false),[notice,setNotice]=useState('');return <details><summary>Background reminder connections</summary><p>Revoke all of your read-only reminder connections in this workspace. Operator and encrypted-vault connections stay separate.</p><button className="button secondary" disabled={busy} onClick={async()=>{setBusy(true);setNotice('');try{await api('/reminder-connections/revoke',{});setNotice('Your reminder connections in this workspace were revoked.');}catch(e){setNotice(e.message);}finally{setBusy(false);}}}>Revoke my reminder connections</button>{notice&&<p role="status">{notice}</p>}</details>;
}
