"""Bounded lockfile inventory extraction. No installers, URL fetches or source retention."""
import hashlib
import json
import re
import tomllib
from collections import Counter
from urllib.parse import urlsplit,unquote
from typing import Literal

MAX_BYTES=1_048_576
MAX_PACKAGES=500
MAX_RECORDS=10000
FORMATS=('requirements','package-json','package-lock','uv-lock','exact-inventory')
DependencyFormat=Literal['requirements','package-json','package-lock','uv-lock','exact-inventory']


def pin_id(package):
    return hashlib.sha256(json.dumps([package['ecosystem'],package['name'],package['version']],separators=(',',':')).encode()).hexdigest()


def pin(ecosystem,name,version,line=0):
    if not isinstance(name,str) or not isinstance(version,str) or len(name)>214 or len(version)>100:raise ValueError()
    if ecosystem=='npm':
        if not re.fullmatch(r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*',name) or not re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?',version):raise ValueError()
    elif ecosystem=='PyPI':
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?',name) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+!_-]*',version):raise ValueError()
        name=re.sub(r'[-_.]+','-',name.lower())
    else:raise ValueError()
    return dict(ecosystem=ecosystem,name=name,version=version,line=line)


def json_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON keys are unsupported.')
        result[key]=value
    return result


def public_registry(url,ecosystem,name=''):
    try:
        parsed=urlsplit(url)
        if parsed.scheme!='https' or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.query or parsed.fragment:return False
        return parsed.hostname=='pypi.org' and parsed.path.rstrip('/')=='/simple' if ecosystem=='PyPI' else parsed.hostname=='registry.npmjs.org' and unquote(parsed.path).startswith('/'+name+'/-/')
    except (ValueError,TypeError,AttributeError):return False


def inventory(text,format,selection=None):
    try:
        if not isinstance(text,str) or len(text.encode('utf-8'))>MAX_BYTES:raise ValueError('Dependency source exceeds 1 MiB.')
    except UnicodeError as error:raise ValueError('Dependency source must be valid UTF-8.') from error
    if format not in FORMATS:raise ValueError('Unsupported dependency format; no substitute parser was used.')
    packages={};reasons=Counter();skipped=[];records=0;roots=0;duplicates=0
    def skip(reason,message=None):
        reasons[reason]+=1
        if len(skipped)<20:skipped.append(message or reason)
    def add(ecosystem,name,version,line=0):
        nonlocal duplicates
        try:value=pin(ecosystem,name,version,line)
        except ValueError:skip('Unsupported package identity or non-exact version.');return
        key=pin_id(value)
        if key in packages:duplicates+=1
        else:packages[key]=value
        if len(packages)>MAX_PACKAGES:raise ValueError('Inventory exceeds 500 unique package/version pairs; split the project explicitly.')
    def record():
        nonlocal records
        records+=1
        if records>MAX_RECORDS:raise ValueError('Dependency source exceeds 10,000 records.')
    if format=='requirements':
        versions={}
        for line,raw in enumerate(text.splitlines(),1):
            raw=raw.strip()
            if not raw or raw.startswith('#'):continue
            record();match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:#.*)?',raw)
            if match:
                name=re.sub(r'[-_.]+','-',match[1].lower())
                if name in versions and versions[name]!=match[2]:raise ValueError('Requirements contain conflicting exact versions; use a lockfile for version variants.')
                versions[name]=match[2]
                add('PyPI',match[1],match[2],line)
            else:skip('Not an unconditional exact pin.',f'Line {line}: not an unconditional exact pin.')
    else:
        try:
            manifest=tomllib.loads(text) if format=='uv-lock' else json.loads(text,object_pairs_hook=json_object)
            if not isinstance(manifest,dict):raise ValueError()
        except (ValueError,TypeError,RecursionError):raise ValueError('Invalid dependency document for the selected format.') from None
        if format=='package-json':
            for group in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
                values=manifest.get(group,{})
                if not isinstance(values,dict):raise ValueError('package.json must contain dependency maps.')
                for name,version in values.items():record();add('npm',name,version)
        elif format=='exact-inventory':
            values=manifest.get('packages')
            if set(manifest)!={'packages'} or not isinstance(values,list):raise ValueError('Exact inventory requires a packages list only.')
            for item in values:
                record()
                if not isinstance(item,dict) or set(item)!={'ecosystem','name','version'}:skip('Unsupported exact inventory record.');continue
                add(item['ecosystem'],item['name'],item['version'])
        elif format=='package-lock':
            if type(manifest.get('lockfileVersion')) is not int or manifest['lockfileVersion'] not in (2,3) or not isinstance(manifest.get('packages'),dict):raise ValueError('Use package-lock.json lockfileVersion 2 or 3 with a packages map.')
            for path,item in manifest['packages'].items():
                record()
                if path=='':roots+=1;continue
                if not isinstance(item,dict):skip('Malformed lock package record.');continue
                if item.get('link'):skip('Workspace/link dependency was not assessed.');continue
                match=re.search(r'(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)$',path)
                if not match:skip('Non-registry workspace record was not assessed.');continue
                name=item.get('name',match[1])
                if not isinstance(name,str) or not public_registry(item.get('resolved'), 'npm',name):skip('Registry origin missing, unsupported or not a standard npm tarball.');continue
                add('npm',name,item.get('version'))
        else:
            if type(manifest.get('version')) is not int or manifest['version']!=1 or type(manifest.get('revision',0)) is not int or manifest.get('revision',0) not in (0,1,2,3) or not isinstance(manifest.get('package'),list):raise ValueError('Use uv.lock version 1, revisions 0–3, with package records.')
            for item in manifest['package']:
                record()
                if not isinstance(item,dict):skip('Malformed uv package record.');continue
                source=item.get('source')
                if isinstance(source,dict) and source in ({'editable':'.'},{'virtual':'.'}):roots+=1;continue
                if not isinstance(source,dict) or set(source)!={'registry'} or not public_registry(source.get('registry'),'PyPI'):skip('Local/git/private-index package was not assessed.');continue
                add('PyPI',item.get('name'),item.get('version'))
    if selection is not None:
        if not isinstance(selection,list) or len(selection)>MAX_PACKAGES or any(not isinstance(key,str) or key not in packages for key in selection) or len(selection)!=len(set(selection)):raise ValueError('Dependency selection changed or contains unsupported pins; preview the current source again.')
        chosen=set(selection)
    else:chosen=set(packages)
    selected=[value for key,value in packages.items() if key in chosen]
    count=sum(reasons.values())
    if count>len(skipped):skipped.append(f'{count-len(skipped)} additional records were skipped; see reason counts.')
    coverage=dict(format=format,records=records,root_records=roots,duplicate_records=duplicates,unique_packages=len(packages),selected=len(selected),excluded=len(packages)-len(selected),skipped_records=count,skipped_reasons=dict(reasons))
    return dict(packages=selected,skipped=skipped,coverage=coverage)


def preview(text,format):
    parsed=inventory(text,format)
    return dict(packages=[dict(**value,id=pin_id(value)) for value in parsed['packages']],coverage=parsed['coverage'],skipped=parsed['skipped'],limits='Exact locked identities only, including dev/optional/platform variants present in the file. Registry metadata is not proof of public availability, installation or integrity. Exclude private package names before approving OSV transmission. No files, paths, URLs, tokens or scripts are retained or executed.')


def apply_coverage(result,scope):
    result['dependency_inventory']=scope['coverage'];result['skipped']=scope['skipped']
    if scope['coverage']['skipped_records'] or scope['coverage']['excluded']:
        result['error']=result.get('error') or 'Project inventory coverage excludes records; selected exact pins and advisory coverage are reported separately.'
    return result
