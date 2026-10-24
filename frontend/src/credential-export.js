import {isArchived} from './entry-history';

export function exportableLogins(entries,includeArchived=false) {
  return entries.filter(entry=>entry.type==='login'&&(includeArchived||!isArchived(entry)));
}

// Preserve credential bytes. Spreadsheet formula escaping would change passwords.
// This file is intended for password-manager import, never spreadsheet execution.
export function credentialCsv(entries,includeArchived=false) {
  const logins=exportableLogins(entries,includeArchived);
  if(!logins.length)throw new Error('No login entries are selected for export.');
  const quote=value=>'"'+String(value??'').replaceAll('"','""')+'"';
  return [['name','url','username','password'],...logins.map(entry=>[entry.title,entry.origin,entry.username,entry.password])]
    .map(row=>row.map(quote).join(',')).join('\r\n')+'\r\n';
}

export function downloadCredentialCsv(entries,includeArchived=false) {
  const blob=new Blob([credentialCsv(entries,includeArchived)],{type:'text/csv;charset=utf-8'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download='sentinelops-logins.csv';
  try{link.click();}finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
