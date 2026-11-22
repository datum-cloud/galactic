#!/usr/bin/env python3
"""Retain verified image-only containerd stores across fresh Kind clusters."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import yaml

LAB = Path(__file__).resolve().parents[1]
OUTPUT = LAB.parents[1] / 'bin/lab-node-cache'
SITES = ('dfw', 'sjc', 'iad')
IMAGE = 'kindest/node:galactic'
HELPER = 'registry:3.0.0'
PREFIX = 'galactic-lab-images-'
LABEL = 'lab.galactic.datumapis.com/node-images'
VERSION = 1


def run(*args, capture=False, data=None):
    result = subprocess.run(args, check=True, text=True, input=data,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def inspect(kind, name):
    result = subprocess.run(['docker', kind, 'inspect', name], capture_output=True, text=True)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def nodes():
    result = []
    for site in SITES:
        config = yaml.safe_load((LAB / 'node_files' / site / 'config.yaml').read_text())
        counts = {}
        for entry in config['nodes']:
            role = entry['role']
            counts[role] = counts.get(role, 0) + 1
            name = f'{site}-{role}' + (str(counts[role]) if counts[role] > 1 else '')
            result.append((site, name, entry))
    return result


def owned(volume):
    if not volume['Name'].startswith(PREFIX) or (volume.get('Labels') or {}).get(LABEL) != 'true':
        raise RuntimeError('Node image cache is not lab-owned; refusing to modify it')
    return volume


def helper(volume, command, *, capture=False, data=None):
    return run('docker', 'run', '--rm', '-i', '--network=none', '--read-only',
               '--mount', f'type=volume,src={volume},dst=/cache',
               '--entrypoint', '/bin/sh', HELPER, '-ec', command, capture=capture, data=data)


def read_state(volume):
    text = helper(volume, 'if test -f /cache/state.json; then cat /cache/state.json; fi', capture=True)
    try:
        state = json.loads(text) if text else {}
    except json.JSONDecodeError:
        return {}
    return state if isinstance(state, dict) else {}


def write_state(volume, state):
    helper(volume, 'cat > /cache/state.tmp; mv /cache/state.tmp /cache/state.json',
           data=json.dumps(state) + '\n')


def containers():
    ids = run('docker', 'ps', '-aq', capture=True).split()
    if not ids:
        return []
    # Do not capture container environments or credentials.
    lines = run('docker', 'inspect', '--format', '{{json .Mounts}}', *ids, capture=True)
    return [json.loads(line) for line in lines.splitlines()]


def mounted(volume, all_mounts):
    root = volume['Mountpoint'].rstrip('/')
    return any(mount.get('Source') == root or mount.get('Source', '').startswith(root + '/')
               for mounts in all_mounts for mount in mounts)


def remove(volume):
    owned(volume)
    if mounted(volume, containers()):
        raise RuntimeError(f'{volume["Name"]}: cache is mounted; destroy its cluster first')
    run('docker', 'volume', 'rm', volume['Name'])


def reusable(state, base):
    return state.get('version') == VERSION and state.get('base') == base and state.get('clean') is True


def prepare_volume(name, base):
    volume_name = PREFIX + name
    volume = inspect('volume', volume_name)
    if volume:
        owned(volume)
        if mounted(volume, containers()):
            raise RuntimeError(f'{name}: node cache is still mounted')
        state = read_state(volume_name)
        if not reusable(state, base):
            print(f'{name}: discarding dirty or incompatible image cache', flush=True)
            remove(volume)
            volume = None
        else:
            print(f'{name}: reusing verified image cache', flush=True)
    if volume is None:
        run('docker', 'volume', 'create', '--label', f'{LABEL}=true', volume_name)
        # A stopped image's initial store has no pods or Kubernetes state.
        # Copy with xattrs/device entries intact, as required by overlayfs.
        run('docker', 'run', '--rm', '--privileged', '--network=none',
            '--mount', f'type=volume,src={volume_name},dst=/cache',
            '--entrypoint', '/bin/bash', IMAGE, '-ec',
            'mkdir -p /cache/data; cp -a /var/lib/containerd/. /cache/data/')
        volume = owned(inspect('volume', volume_name))
    # An interrupted create or destroy must never make an active runtime reusable.
    write_state(volume_name, {'version': VERSION, 'base': base, 'clean': False})
    return volume['Mountpoint'] + '/data'


def cache_mount(entry, path):
    if any(m['containerPath'] == '/var/lib/containerd' for m in entry.get('extraMounts', [])):
        raise RuntimeError('Kind configuration already supplies a containerd store')
    entry.setdefault('extraMounts', []).append({'hostPath': path, 'containerPath': '/var/lib/containerd'})


def base_fingerprint(image=IMAGE):
    info = json.loads(run('docker', 'image', 'inspect', image, capture=True))[0]
    # BuildKit can replace index attestations on a cached build. Invalidate
    # for runtime configuration or filesystem changes, not provenance timestamps.
    content = {key: info[key] for key in ('Config', 'RootFS', 'Os', 'Architecture')}
    return 'sha256:' + hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def prepare():
    entries = nodes()
    # Inspect Docker successfully before treating an individual missing node as absent.
    containers()
    if any(inspect('container', name) for _, name, _ in entries):
        raise RuntimeError('Kind nodes already exist; run task destroy before deploy')
    base = base_fingerprint()
    # Helpers are short-lived Docker containers. Serialize cache maintenance so
    # another helper cannot disappear during the mounted-volume safety check.
    paths = {name: prepare_volume(name, base) for _, name, _ in entries}
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for site in SITES:
        config = yaml.safe_load((LAB / 'node_files' / site / 'config.yaml').read_text())
        for entry, (_, name, _) in zip(config['nodes'], [e for e in entries if e[0] == site]):
            cache_mount(entry, paths[name])
        (OUTPUT / f'{site}.yaml').write_text(yaml.safe_dump(config, sort_keys=False))


def activate():
    for _, name, _ in nodes():
        volume = owned(inspect('volume', PREFIX + name))
        node = inspect('container', name)
        if not node or not any(m.get('Source') == volume['Mountpoint'] + '/data'
                               and m['Destination'] == '/var/lib/containerd' for m in node['Mounts']):
            raise RuntimeError(f'{name}: expected image cache is not attached')
        state = read_state(volume['Name'])
        if state.get('base') != base_fingerprint(node['Image']):
            raise RuntimeError(f'{name}: node image changed after cache preparation')
        state.update(clean=False, container=node['Id'])
        write_state(volume['Name'], state)


def parallel(fn, names):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(fn, name) for name in names]
        for future in futures:
            future.result()


def no_writable_snapshots(table):
    for line in table.splitlines()[1:]:
        if line.strip() and line.split()[-1].lower() != 'committed':
            raise RuntimeError('Writable or temporary snapshots remain; cache cannot be reused')


def stop_pods(name, host_network):
    ids = run('docker', 'exec', name, 'crictl', 'pods', '-q', capture=True).split()
    selected = []
    for pod in ids:
        status = json.loads(run('docker', 'exec', name, 'crictl', 'inspectp', pod, capture=True))['status']
        network = status['linux']['namespaces']['options']['network']
        if network not in ('NODE', 'POD', 0, 2):
            raise RuntimeError(f'{name}: unsupported pod network namespace mode')
        if (network in ('NODE', 2)) == host_network:
            selected.append(pod)
    if selected:
        run('docker', 'exec', name, 'crictl', '--timeout=120s', 'stopp', *selected)


def empty_runtime(name):
    pods = run('docker', 'exec', name, 'crictl', 'pods', '-q', capture=True).split()
    remaining = run('docker', 'exec', name, 'crictl', 'ps', '-a', '-q', capture=True).split()
    if remaining:
        run('docker', 'exec', name, 'crictl', '--timeout=120s', 'rm', '-f', *remaining)
    if pods:
        run('docker', 'exec', name, 'crictl', '--timeout=120s', 'rmp', *pods)
    deadline = time.monotonic() + 30
    while True:
        try:
            verify_empty_runtime(name)
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
    run('docker', 'exec', name, 'systemctl', 'stop', 'containerd')
    # CRI metadata directories must be empty as well as the runtime API.
    run('docker', 'exec', name, 'bash', '-ec',
        'for d in /var/lib/containerd/io.containerd.grpc.v1.cri/containers '
        '/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes; do '
        'test ! -d "$d" || test -z "$(ls -A "$d")"; done')
    print(f'{name}: image-only cache verified; containerd stopped', flush=True)


def verify_empty_runtime(name):
    for args in (('ps', '-a', '-q'), ('pods', '-q')):
        if run('docker', 'exec', name, 'crictl', *args, capture=True):
            raise RuntimeError(f'{name}: CRI runtime is not empty')
    for namespace in run('docker', 'exec', name, 'ctr', 'namespaces', 'ls', '-q', capture=True).split():
        for resource in ('containers', 'tasks'):
            if run('docker', 'exec', name, 'ctr', '-n', namespace, resource, 'ls', '-q', capture=True):
                raise RuntimeError(f'{name}: containerd {resource} remain in {namespace}')
        sandboxes = run('docker', 'exec', name, 'ctr', '-n', namespace, 'sandboxes', 'ls', capture=True)
        if any(line.strip() for line in sandboxes.splitlines()[1:]):
            raise RuntimeError(f'{name}: containerd sandboxes remain in {namespace}')
        # These are the local snapshotters in the pinned Kind image. The
        # rootless fuse proxy has a separate store outside this cache.
        for snapshotter in ('overlayfs', 'native'):
            table = run('docker', 'exec', name, 'ctr', '-n', namespace, 'snapshots',
                        '--snapshotter', snapshotter, 'ls', capture=True)
            no_writable_snapshots(table)
    files = run('docker', 'exec', name, 'bash', '-ec',
                'for d in /var/lib/containerd/io.containerd.runtime.v2.task '
                '/var/lib/containerd/io.containerd.sandbox.controller.v1.shim; do '
                'if test -d "$d"; then find "$d" -mindepth 1 ! -type d -print; fi; done',
                capture=True)
    if files:
        raise RuntimeError(f'{name}: runtime files remain in the image store')


def release():
    cached = {}
    for _, name, _ in nodes():
        node = inspect('container', name)
        if not node:
            continue
        volume = inspect('volume', PREFIX + name)
        if not volume or not any(m.get('Source') == volume['Mountpoint'] + '/data'
                                 for m in node['Mounts']):
            continue  # Older deployments have disposable stores and need no cache teardown.
        owned(volume)
        state = read_state(volume['Name'])
        if not state.get('container') and state.get('clean') is not True:
            continue  # An incomplete create leaves a dirty store to discard.
        if state.get('container') != node['Id']:
            raise RuntimeError(f'{name}: unverified cache lease; destroy and discard this cache')
        cached[name] = state
    parallel(lambda name: run('docker', 'exec', name, 'systemctl', 'stop', 'kubelet'), cached)
    # Keep network agents alive until all ordinary pods have completed CNI DEL,
    # and API servers alive until worker agents have stopped.
    parallel(lambda name: stop_pods(name, False), cached)
    parallel(lambda name: stop_pods(name, True), [n for n in cached if '-control-plane' not in n])
    parallel(lambda name: stop_pods(name, True), [n for n in cached if '-control-plane' in n])
    parallel(empty_runtime, cached)
    return cached


def destroy():
    cached = {}
    failed = False
    try:
        cached = release()
    except Exception as error:
        print(f'Cache cleanup failed: {error}', file=sys.stderr)
        failed = True
    for site in SITES:
        try:
            run('kind', 'delete', 'cluster', '--name', site)
        except subprocess.CalledProcessError:
            failed = True
    if failed:
        raise RuntimeError('Cluster teardown failed; image caches remain dirty')
    containers()  # A failed Docker query must not mean that nodes are absent.
    if any(inspect('container', name) for _, name, _ in nodes()):
        raise RuntimeError('Cluster nodes remain; image caches cannot be reused')
    # Keep stores dirty until verified runtimes and their node containers are gone.
    for name, state in cached.items():
        state.update(clean=True, container=None,
                     verified={'containers': 0, 'sandboxes': 0, 'tasks': 0, 'writable_snapshots': 0})
        write_state(PREFIX + name, state)


def clean():
    for name in run('docker', 'volume', 'ls', '-q', '--filter', f'label={LABEL}=true', capture=True).split():
        remove(owned(inspect('volume', name)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'activate', 'destroy', 'clean'))
    action = parser.parse_args().action
    {'prepare': prepare, 'activate': activate, 'destroy': destroy, 'clean': clean}[action]()
