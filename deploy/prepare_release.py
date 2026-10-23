"""Build web and companion together in a new isolated candidate directory."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from companion.package_extension import package_extension
from deploy.build_provenance import source_digest,stamp,revision
from deploy.build_release import build_release


def prepare(root, destination, *, node='node', run=subprocess.run):
    root=Path(root).resolve();destination=Path(destination).absolute()
    # Never target a pre-existing tree or the installed frontend/extension builds.
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError('Choose a new candidate directory under an existing private parent.')
    destination.mkdir(mode=0o700)
    before=source_digest(root);commit=revision(root)
    vite=root/'frontend/node_modules/vite/bin/vite.js'
    if not vite.is_file():raise ValueError('Install the pinned frontend dependencies before preparing a release.')
    web=destination/'frontend/dist';extension=destination/'companion/extension/dist'
    commands=[
        ([node,str(vite),'build','--outDir',str(web),'--emptyOutDir'],root/'frontend'),
    ]
    for component in ('content','popup','background'):
        commands.append(([node,str(vite),'build','--config',str(root/f'companion/extension/vite.{component}.config.js'),'--outDir',str(extension)],root))
    for args,cwd in commands:run(args,cwd=cwd,check=True,timeout=180,shell=False)
    # Popup's configured public directory supplies the manifest; the final worker
    # build must not replace it with its unbundled public source counterpart.
    report=package_extension(extension,destination/'companion/extension/sentinelops-companion.zip',root/'companion/extension/public/manifest.json')
    if revision(root)!=commit:raise ValueError('Git revision changed during build; prepare a new candidate.')
    stamp(root,destination,before)
    release=build_release(root,destination/'sentinelops-release.tar.gz',build_root=destination)
    result={'release':release,'companion':{'version':report['version'],'sha256':report['sha256']},'published':False,'deployed':False}
    with (destination/'candidate.json').open('x',encoding='utf-8') as handle:json.dump(result,handle,sort_keys=True,indent=2);handle.write('\n')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',required=True)
    parser.add_argument('--node',default='node')
    args=parser.parse_args(argv)
    try:result=prepare(ROOT,args.destination,node=args.node)
    except (OSError,ValueError,subprocess.SubprocessError):
        parser.exit(1,'Release preparation failed. Existing installed builds were not targeted; inspect the disposable candidate and build output.\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
