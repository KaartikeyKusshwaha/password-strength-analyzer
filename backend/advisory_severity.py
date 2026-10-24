"""OSV-reported CVSS base ratings. These do not establish local exploitability."""
import re

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

MAX_RATINGS = 8
MAX_DISPLAYED = 20
RANK = {'none':0, 'low':1, 'medium':2, 'high':3, 'critical':4}
BASE = {
    'CVSS_V2': ('AV','AC','Au','C','I','A'),
    'CVSS_V3': ('AV','AC','PR','UI','S','C','I','A'),
    'CVSS_V4': ('AV','AC','AT','PR','UI','VC','VI','VA','SC','SI','SA'),
}


def parse_rating(value, advisory):
    if not isinstance(value, dict):
        return None
    kind, vector = value.get('type'), value.get('score')
    if not isinstance(kind,str) or kind not in BASE or not isinstance(vector,str) or not 1<=len(vector)<=1024 or not re.fullmatch(r'[A-Za-z0-9:/.]+',vector):
        return None
    prefix = vector.split('/',1)[0]
    if kind=='CVSS_V3' and prefix not in {'CVSS:3.0','CVSS:3.1'} or kind=='CVSS_V4' and prefix!='CVSS:4.0' or kind=='CVSS_V2' and vector.startswith('CVSS:'):
        return None
    model = {'CVSS_V2':CVSS2,'CVSS_V3':CVSS3,'CVSS_V4':CVSS4}[kind]
    try:
        # Validate the entire supplied vector before discarding optional metrics.
        model(vector)
        parts=vector.split('/') if kind=='CVSS_V2' else vector.split('/')[1:]
        metrics=dict(part.split(':',1) for part in parts)
        if len(metrics)!=len(parts):
            return None
        base='/'.join(key+':'+metrics[key] for key in BASE[kind])
        if kind!='CVSS_V2':base=prefix+'/'+base
        calculated=model(base)
        score=float(calculated.scores()[0])
        rating=calculated.severities()[0].lower()
        if not 0<=score<=10 or rating not in RANK:
            return None
    except (CVSSError,ValueError,KeyError,TypeError):
        return None
    source=value.get('source')
    return {'advisory':advisory,'version':'2.0' if kind=='CVSS_V2' else prefix[5:],
            'base_score':score,'rating':rating,'vector':base,'reported_vector':vector,
            'declared_source':source if isinstance(source,str) and source in {'NVD','CNA','SELF'} else None}


def same_package(left, right):
    if not isinstance(left,dict) or left.get('ecosystem')!=right['ecosystem'] or not isinstance(left.get('name'),str):
        return False
    if right['ecosystem']=='PyPI':
        return re.sub(r'[-_.]+','-',left['name']).lower()==re.sub(r'[-_.]+','-',right['name']).lower()
    return left['name']==right['name']


def record_ratings(record, package):
    if record is None:
        return [],0,False
    affected=record.get('affected',[])
    if not isinstance(affected,list) or len(affected)>100 or any(not isinstance(item,dict) for item in affected):
        return [],1,True
    package_specific=any('severity' in item for item in affected)
    ignored,truncated=0,False
    if package_specific:
        if 'severity' in record:
            return [],1,False  # OSV forbids simultaneous global/package severity.
        matching=[item for item in affected if same_package(item.get('package'),package)]
        candidates=[]
        for item in matching:
            # A batch match identifies the sole package entry. For several entries,
            # use explicit version membership; do not guess ecosystem range rules.
            versions=item.get('versions',[])
            if len(matching)>1 and (not isinstance(versions,list) or package['version'] not in versions):
                ignored+=1
                continue
            severity=item.get('severity',[])
            if not isinstance(severity,list):ignored+=1;continue
            candidates.extend(severity[:MAX_RATINGS+1])
            if len(severity)>MAX_RATINGS:truncated=True
    else:
        candidates=record.get('severity',[])
        if not isinstance(candidates,list):return [],1,False
    if len(candidates)>MAX_RATINGS:truncated=True
    ratings=[]
    for candidate in candidates[:MAX_RATINGS]:
        value=parse_rating(candidate,record['id'])
        if value:ratings.append(value)
        else:ignored+=1
    unique={tuple(value.items()):value for value in ratings}
    return list(unique.values()),ignored,truncated


def assess(identifiers, records, package):
    ratings=[];scored=ignored=0;truncated=False
    for identifier in identifiers:
        values,discarded,limited=record_ratings(records.get(identifier),package)
        scored+=bool(values);ignored+=discarded;truncated=truncated or limited;ratings.extend(values)
    # Preserve distinct provider ratings. Rank the highest available category;
    # numbers from different CVSS generations are not interchangeable risk scores.
    ratings.sort(key=lambda value:(-RANK[value['rating']],-value['base_score'],-float(value['version']),value['advisory'],value['vector'],value['declared_source'] or ''))
    if len(ratings)>MAX_DISPLAYED:truncated=True
    return {'status':'unavailable' if not ratings else 'available' if scored==len(identifiers) and not ignored and not truncated else 'partial',
            'selected':ratings[0] if ratings else None,'ratings':ratings[:MAX_DISPLAYED],
            'scored_advisories':scored,'total_advisories':len(identifiers),'ignored_ratings':ignored,'truncated':truncated}
