export const PRIMARY_PAGES = new Set(['clients','workflows','vault','companions','settings']);
export const ADVANCED_PAGES = new Set(['overview','assets','scans','reviews','findings','tasks','investigations','agents','watches','reports']);

export function readRoute(location, advancedEnabled){
  const requested=new URLSearchParams(location.hash.slice(1)).get('page');
  if(location.pathname==='/advanced' && advancedEnabled){
    return {advanced:true,page:ADVANCED_PAGES.has(requested)?requested:'overview'};
  }
  return {advanced:false,page:location.pathname==='/'&&PRIMARY_PAGES.has(requested)?requested:'vault'};
}

export function pageRoute(page,advancedEnabled){
  if(ADVANCED_PAGES.has(page))return advancedEnabled?{advanced:true,page,url:'/advanced#page='+page}:{advanced:false,page:'vault',url:'/'};
  const selected=PRIMARY_PAGES.has(page)?page:'vault';
  return {advanced:false,page:selected,url:selected==='vault'?'/':'/#page='+selected};
}
