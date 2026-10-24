import { validOrigin, parseOtpAuth, decodeBase32 } from './vault-crypto';

export function parseCsv(text) {
  if(typeof text!=='string' || new TextEncoder().encode(text).length>2000000)throw new Error('Choose a CSV under 2 MB.');
  text=text.replace(/^\uFEFF/,'');
  const rows=[];let row=[],field='',quoted=false,closed=false;
  for(let index=0;index<text.length;index++){
    const char=text[index];
    if(quoted){if(char==='"'){if(text[index+1]==='"'){field+='"';index++;}else{quoted=false;closed=true;}}else field+=char;continue;}
    if(closed && ![',','\r','\n'].includes(char))throw new Error('Malformed CSV after a quoted field.');
    if(char==='"'){if(field)throw new Error('Malformed quote in CSV.');quoted=true;}
    else if(char===','){row.push(field);field='';closed=false;}
    else if(char==='\r' || char==='\n'){if(char==='\r' && text[index+1]==='\n')index++;row.push(field);if(row.some(v=>v.length))rows.push(row);row=[];field='';closed=false;}
    else field+=char;
    if(rows.length>10000)throw new Error('CSV contains too many records.');
  }
  if(quoted)throw new Error('CSV contains an unterminated quoted field.');
  row.push(field);if(row.some(v=>v.length))rows.push(row);
  if(rows.length<2)throw new Error('CSV must contain a header and at least one account row.');
  const headers=rows.shift().map(v=>v.trim().toLowerCase());
  if(new Set(headers).size!==headers.length)throw new Error('CSV contains duplicate column names.');
  if(rows.some(r=>r.length!==headers.length))throw new Error('CSV row lengths do not match the header.');
  return {headers,rows};
}
export function importCredentials(text) {
  const {headers,rows}=parseCsv(text);
  const columns=new Set(headers);
  let format,url,user,password,title,totp;
  if(columns.has('login_uri') && columns.has('login_password')){format='Bitwarden';url='login_uri';user='login_username';password='login_password';title='name';totp='login_totp';}
  else if(columns.has('url') && columns.has('password') && columns.has('username')){format=columns.has('grouping')||columns.has('extra')?'LastPass':columns.has('title')?'1Password':'Chrome / compatible';url='url';user='username';password='password';title=columns.has('title')?'title':'name';totp=columns.has('totp')?'totp':null;}
  else throw new Error('Unsupported CSV columns. Use a Chrome, Bitwarden, 1Password or LastPass login CSV.');
  const entries=[],skipped=[];
  for(let index=0;index<rows.length;index++){
    const value=Object.fromEntries(headers.map((header,i)=>[header,rows[index][i]]));
    if(value.type && !['login','1'].includes(value.type.toLowerCase())){skipped.push({row:index+2,reason:'Non-login item type'});continue;}
    try{
      if(!value[url] || !value[password])throw new Error('Missing website or password');
      const origin=validOrigin(value[url]);
      if(value[password].length>256 || (value[user]||'').length>254)throw new Error('Entry exceeds the current size limit');
      const name=(value[title] || new URL(origin).hostname).slice(0,100);
      entries.push({id:crypto.randomUUID(),type:'login',title:name,origin,username:value[user]||'',password:value[password]});
      if(totp && value[totp]){
        try{const setup=parseOtpAuth(value[totp]);decodeBase32(setup.secret);entries.push({id:crypto.randomUUID(),type:'totp',title:name,...setup});}catch{skipped.push({row:index+2,reason:'Authenticator setup key unsupported; login is included'});}
      }
    }catch(error){skipped.push({row:index+2,reason:error.message});}
  }
  if(!entries.length)throw new Error('No supported HTTPS login entries were found. No data was imported.');
  return {format,entries,skipped};
}
