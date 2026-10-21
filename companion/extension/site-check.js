// No page text, credentials, query strings or cookies are collected.
export function websiteScope(value) {
  const url=new URL(value),host=url.hostname.toLowerCase();
  if(!['https:','http:'].includes(url.protocol) || url.username || url.password ||
    url.port && !['80','443'].includes(url.port) || host==='localhost' ||
    host.endsWith('.localhost') || host.endsWith('.local') ||
    !host.includes('.') || /^[\d.]+$/.test(host) || host.includes(':')) {
    throw new Error('Choose a public website. Device and private-network checks need the device helper.');
  }
  return {origin:url.origin,https:url.protocol==='https:',permission:url.origin+'/*'};
}

export async function checkWebsite(scope,fetcher=fetch) {
  if(!scope.https)return {origin:scope.origin,coverage:'Address check only; no request sent over HTTP.',actions:[{id:'https',title:'Use the HTTPS version of this website.',detail:'This page uses an unencrypted connection. Do not enter passwords here.'}]};
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),10000);
  try {
    const response=await fetcher(scope.origin+'/',{method:'HEAD',credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});
    const actions=[];
    for(const [header,id,title,detail] of [
      ['strict-transport-security','hsts','Ask the site owner to enforce HTTPS.','The response has no HSTS header. This alone does not prove the website is unsafe.'],
      ['content-security-policy','csp','Ask the site owner to review browser content restrictions.','The response has no Content-Security-Policy header. Its absence is a configuration observation.'],
      ['x-content-type-options','mime','Ask the site owner to prevent content-type guessing.','The response has no X-Content-Type-Options header.']
    ])if(!response.headers.get(header))actions.push({id,title,detail});
    return {origin:scope.origin,status:response.status,coverage:'Runs in browser · one cookie-free HTTPS HEAD request to the site root. No redirects, crawling, exploit tests or account access.',actions};
  }catch(error){throw new Error(error.name==='AbortError'?'The check timed out. No safety verdict was produced.':'The site could not be assessed. It may redirect or block this request. No safety verdict was produced.');}
  finally{clearTimeout(timer);}
}
