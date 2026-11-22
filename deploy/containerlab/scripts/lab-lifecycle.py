#!/usr/bin/env python3
"""Deploy and reset the lab through one ordered baseline task sequence."""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parents[1]
STATE = REPO / 'bin/lab-lifecycle'
SITES = ('dfw', 'sjc', 'iad')
TENANTS = ('ns10', 'ns20', 'ns30', 'ns40', 'ns60', 'ns71', 'ns80')
FIXTURES = (*TENANTS, 'ns80-tap', 'gateway-local', 'nat-local')
SYSTEM_NAMESPACES = ('kube-system', 'cert-manager', 'galactic-system')
# The sequence is also used by reset. Infrastructure creation and image builds
# belong only to deploy; reset reuses the recorded immutable image inventory.
BASELINE_TASKS = (
    'deploy:system', 'deploy:cni', 'deploy:lab-xdp-passthrough-compute',
    'deploy:cert-manager', 'deploy:traffic-policy', 'deploy:node-addresses',
    'deploy:fabric', 'deploy:fabric-routing', 'deploy:bmp-collector',
    'deploy:galactic-router', 'deploy:galactic-nat', 'deploy:scenarios',
    'deploy:galactic-gateway', 'deploy:fabric-api', 'deploy:galactic-edge',
)


def run(*args, capture=False, data=None):
    result = subprocess.run(args, cwd=LAB, check=True, text=True, input=data,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def k(site, *args, **kwargs):
    return run('docker', 'exec', '-i', f'{site}-control-plane', 'kubectl', *args, **kwargs)


def get(site, resource, namespace=None):
    args = ['get', resource, '-o', 'json']
    if namespace:
        args += ['-n', namespace]
    return json.loads(k(site, *args, capture=True))


def parallel(fn):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(fn, site) for site in SITES]
        # Executor shutdown waits for other sites even when one fails.
        return {site: future.result() for site, future in zip(SITES, futures)}


def source_hash():
    digest = hashlib.sha256()
    paths = [LAB / 'gvpc.clab.yaml', LAB / 'Taskfile.yaml',
             *sorted((LAB / 'scripts').glob('*.sh')),
             *sorted((LAB / 'scripts').glob('*.py')),
             *sorted((REPO / 'containers').rglob('*')),
             *sorted((LAB / 'containers').rglob('*')), *sorted((LAB / 'node_files').rglob('*')),
             *sorted((LAB / 'group_files').rglob('*')),
             *sorted((LAB / 'resources').rglob('*')),
             *sorted((REPO / 'config').rglob('*'))]
    for path in paths:
        if path.is_file() and path.suffix != '.o':
            digest.update(str(path.relative_to(REPO)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def identities():
    names = [node['metadata']['name'] for site in SITES for node in get(site, 'nodes')['items']]
    return {name: run('docker', 'inspect', '-f', '{{.Id}} {{.State.StartedAt}}', name, capture=True)
            for name in names}


def component(item):
    metadata = item['metadata']
    result = {key: item[key] for key in ('apiVersion', 'kind')}
    result['metadata'] = {key: metadata[key] for key in ('name', 'namespace') if key in metadata}
    if item['kind'] == 'ConfigMap':
        result['data'] = item.get('data', {})
        result['binaryData'] = item.get('binaryData', {})
    else:
        result['spec'] = item['spec']
    return result


def site_snapshot(site):
    items = []
    for namespace in SYSTEM_NAMESPACES:
        items += [component(item) for item in get(site, 'daemonsets,deployments', namespace)['items']]
    items += [component(item) for item in get(site, 'configmaps', 'galactic-system')['items']]
    return {'components': items,
            'namespaces': sorted(item['metadata']['name'] for item in get(site, 'namespaces')['items']),
            'nodes': [{key: item[key] for key in ('metadata', 'spec')}
                      for item in get(site, 'nodes')['items']],
            'fabric': sorted([component(item) for item in
                              get(site, 'fabricrouterdeployments', 'galactic-system')['items']],
                             key=lambda item: item['metadata']['name'])}


def ready(site):
    k(site, 'wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=180s')
    for ns in SYSTEM_NAMESPACES:
        for item in get(site, 'daemonsets,deployments', ns)['items']:
            k(site, '-n', ns, 'rollout', 'status',
              f'{item["kind"]}/{item["metadata"]["name"]}', '--timeout=180s')


def checkpoint():
    parallel(ready)
    image_path = REPO / 'bin/lab-images/inventory.json'
    state = {'version': 1, 'source': source_hash(), 'identities': identities(),
             'images': json.loads(image_path.read_text()), 'sites': parallel(site_snapshot)}
    target = STATE / 'baseline.json'
    temp = target.with_suffix('.tmp')
    temp.write_text(json.dumps(state, indent=2) + '\n')
    temp.replace(target)


def check_fences(records):
    for record in records:
        if (record.get('owner', '').startswith('galactic-worker:')
                or record.get('transitioning') or record.get('pending')):
            raise RuntimeError('Worker ownership or unfinished transfer requires a full redeploy')


def preflight(state):
    if state.get('version') != 1 or state['source'] != source_hash():
        raise RuntimeError('Lab sources differ from the deploy checkpoint; run destroy and deploy')
    if identities() != state['identities']:
        raise RuntimeError('Lab containers differ from the deploy checkpoint; run destroy and deploy')
    for node in state['identities']:
        text = run('docker', 'exec', node, 'sh', '-ec',
                   'test ! -S /run/galactic-worker/worker.sock; '
                   'for f in /var/lib/galactic-edge/ownership/*.json; do '
                   '[ -e "$f" ] || continue; cat "$f"; echo; done', capture=True)
        # Each ownership record is a JSON document; formatting can span lines.
        decoder = json.JSONDecoder()
        records = []
        text = text.strip()
        while text:
            record, end = decoder.raw_decode(text)
            records.append(record)
            text = text[end:].lstrip()
        check_fences(records)
    for site in SITES:
        current = site_snapshot(site)
        added = set(current['namespaces']) - set(state['sites'][site]['namespaces'])
        if added - set(FIXTURES):
            raise RuntimeError(f'{site}: unrecognized namespaces require explicit cleanup or redeploy')
        if current['fabric'] != state['sites'][site]['fabric']:
            raise RuntimeError(f'{site}: fabric activation changed; run destroy and deploy')
        expected = {(i['kind'], i['metadata']['namespace'], i['metadata']['name'])
                    for i in state['sites'][site]['components']}
        actual = {(i['kind'], i['metadata']['namespace'], i['metadata']['name'])
                  for i in current['components']}
        if actual != expected:
            raise RuntimeError(f'{site}: system component inventory changed; run destroy and deploy')


def restore_site(site, saved):
    # Replacing the whole spec removes fields added by kubectl patch/set env,
    # which kubectl apply alone does not own and would leave behind.
    for item in saved['components']:
        fields = ('data', 'binaryData') if item['kind'] == 'ConfigMap' else ('spec',)
        patch = [{'op': 'add', 'path': '/' + field, 'value': item[field]} for field in fields]
        k(site, '-n', item['metadata']['namespace'], 'patch',
          f'{item["kind"]}/{item["metadata"]["name"]}', '--type=json',
          '--patch-file=/dev/stdin', data=json.dumps(patch))
    for item in saved['nodes']:
        patch = [{'op': 'add', 'path': '/metadata/labels', 'value': item['metadata']['labels']},
                 {'op': 'add', 'path': '/spec/taints', 'value': item['spec'].get('taints', [])},
                 {'op': 'add', 'path': '/spec/unschedulable',
                  'value': item['spec'].get('unschedulable', False)}]
        k(site, 'patch', 'node', item['metadata']['name'], '--type=json',
          '--patch-file=/dev/stdin', data=json.dumps(patch))
    # A branch can replace :latest without changing a workload spec. Force
    # replacement of running containers after restoring the saved image tags.
    k(site, '-n', 'galactic-system', 'rollout', 'restart', 'daemonset,deployment')
    ready(site)
    # Namespace deletion waits for CNI DEL and controller finalizers; never
    # force-finalize or remove pinned dataplane state underneath live workloads.
    k(site, 'delete', 'namespace', *FIXTURES, '--ignore-not-found', '--wait=true', '--timeout=240s')


def lifecycle(mode, output=None):
    STATE.mkdir(parents=True, exist_ok=True)
    output = Path(output) if output else STATE / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output.mkdir(parents=True, exist_ok=False)
    os.environ['LAB_TIMING_DIR'] = str(output.resolve() / 'sites')
    start = time.monotonic()
    def step(name, fn):
        before = time.monotonic()
        code = 1
        try:
            fn()
            code = 0
        finally:
            with (output / 'timings.tsv').open('a') as stream:
                stream.write(f'{name}\t{time.monotonic()-before:.3f}\t{code}\n')
    def task(name):
        step(name, lambda: run('task', name))
    try:
        if mode == 'deploy':
            # A failed deploy must not leave a usable checkpoint from an older run.
            (STATE / 'baseline.json').unlink(missing_ok=True)
            task('build')
            task('host-setup')
            task('images:publish')
            task('deploy:clusters')
            task('deploy:topology')
            task('deploy:lab-xdp-passthrough')
        else:
            if not (STATE / 'baseline.json').is_file():
                raise RuntimeError('No successful deploy checkpoint; run task destroy and task deploy')
            state = json.loads((STATE / 'baseline.json').read_text())
            step('reset:preflight', lambda: preflight(state))
            image_path = REPO / 'bin/lab-images/inventory.json'
            # Invalidate before the first mutation; failed resets require recovery.
            (STATE / 'baseline.json').unlink()
            # A branch check may publish different :latest images. Restore the
            # checkpoint's digest inventory, without resolving mutable tags again.
            image_path.write_text(json.dumps(state['images'], indent=2) + '\n')
        task('images:load')
        if mode == 'reset':
            step('reset:restore', lambda: parallel(lambda site: restore_site(site, state['sites'][site])))
            task('deploy:lab-xdp-passthrough')
        for name in BASELINE_TASKS:
            task(name)
        step('checkpoint', checkpoint)
    finally:
        (output / 'elapsed-seconds').write_text(f'{time.monotonic()-start:.3f}\n')
        print(f'Lifecycle evidence: {output}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('deploy', 'reset'))
    parser.add_argument('--output')
    args = parser.parse_args()
    lifecycle(args.mode, args.output)
