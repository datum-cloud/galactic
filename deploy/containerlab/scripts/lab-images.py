#!/usr/bin/env python3
"""Publish unchanged lab images once and pull them concurrently into Kind nodes."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import time
import urllib.request

import yaml

LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parents[1]
CACHE = REPO / 'bin/lab-images'
CRANE = REPO / 'bin/crane'
REGISTRY = 'galactic-lab-registry'
HOST = 'localhost:5001'
NODE_HOST = f'{REGISTRY}:5000'
LABEL = 'lab.galactic.datumapis.com/registry'
SITES = ('dfw', 'sjc', 'iad')
FABRIC = ['dfw-worker', 'dfw-worker2', 'dfw-worker3', 'dfw-worker4',
          'sjc-worker', 'sjc-worker2', 'iad-worker', 'iad-worker2', 'iad-worker3']
EDGE = ['dfw-worker2', 'dfw-worker3', 'sjc-worker2', 'iad-worker2']
LOCAL = {
    'fabric-router:latest': FABRIC, 'fabric-api:latest': FABRIC,
    'galactic-router:latest': FABRIC,
    'galactic-cni:latest': [n for n in FABRIC if n != 'iad-worker3'],
    'galactic-nat:latest': EDGE, 'galactic-gateway:latest': EDGE,
    'galactic-controller:latest': FABRIC, 'fabric-router-controller:latest': FABRIC,
    **{f'{image}:latest': EDGE[:2] for image in
       ('galactic-edge', 'edge-provider', 'masque-provider', 'masque-service')},
    'masque-authority:latest': ['dfw-worker'],
}


def run(*args, capture=False):
    result = subprocess.run(args, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def crane(*args):
    return run(str(CRANE), *args, capture=True)


def canonical(image):
    # CRI normalizes a reference carrying both a tag and a digest to the
    # repository@digest form. Store that same name in containerd.
    if '@' in image:
        name, digest = image.rsplit('@', 1)
        if ':' in name.rsplit('/', 1)[-1]:
            name = name.rsplit(':', 1)[0]
        image = name + '@' + digest
    first = image.split('/')[0]
    if '/' not in image:
        return 'docker.io/library/' + image
    if '.' not in first and ':' not in first and first != 'localhost':
        return 'docker.io/' + image
    return image


def image_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'image' and isinstance(child, str):
                yield child
            else:
                yield from image_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from image_refs(child)


def yaml_images(text):
    for doc in yaml.safe_load_all(text):
        yield from image_refs(doc)


def native_platform():
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('The lab image loader supports amd64 and arm64 hosts')
    return 'linux/' + arch


def node_scheduling():
    result = {}
    for site in SITES:
        config = yaml.safe_load((LAB / 'node_files' / site / 'config.yaml').read_text())
        workers = 0
        for node in config['nodes']:
            if node['role'] == 'control-plane':
                name = f'{site}-control-plane'
                taints = [{'key': 'node-role.kubernetes.io/control-plane', 'effect': 'NoSchedule'}]
            else:
                workers += 1
                name = f'{site}-worker' + (str(workers) if workers > 1 else '')
                taints = []
            for patch in node.get('kubeadmConfigPatches', []):
                taints.extend(yaml.safe_load(patch).get('nodeRegistration', {}).get('taints', []))
            role_labels = {'node-role.kubernetes.io/control-plane': ''} if node['role'] == 'control-plane' else {}
            labels = {**role_labels, 'kubernetes.io/os': 'linux', 'kubernetes.io/arch': native_platform().split('/')[1],
                      'kubernetes.io/hostname': name, **node.get('labels', {})}
            result[name] = {'labels': labels, 'taints': taints}
    return result


def tolerates(toleration, taint):
    if toleration.get('effect') and toleration['effect'] != taint['effect']:
        return False
    if toleration.get('operator', 'Equal') == 'Exists':
        return not toleration.get('key') or toleration['key'] == taint['key']
    return (toleration.get('key') == taint['key']
            and toleration.get('value', '') == taint.get('value', ''))


def chart_placements(text, nodes):
    # Affinity can narrow this superset further. Never exclude a node based
    # on preferred affinity or an assumption about the scheduler's choice.
    scheduling = node_scheduling()
    def visit(value):
        if isinstance(value, dict):
            if 'containers' in value:
                eligible = []
                for name in nodes:
                    node = scheduling[name]
                    if value.get('nodeName'):
                        if value['nodeName'] == name:
                            eligible.append(name)
                        continue
                    if any(node['labels'].get(key) != expected
                           for key, expected in value.get('nodeSelector', {}).items()):
                        continue
                    if any(taint['effect'] in ('NoSchedule', 'NoExecute')
                           and not any(tolerates(t, taint) for t in value.get('tolerations', []))
                           for taint in node['taints']):
                        continue
                    eligible.append(name)
                for ref in image_refs(value):
                    yield ref, eligible
            else:
                for child in value.values():
                    yield from visit(child)
        elif isinstance(value, list):
            for child in value:
                yield from visit(child)
    for doc in yaml.safe_load_all(text):
        yield from visit(doc)


def external_images():
    versions = dict(re.findall(r'^(\w+)=(\S+)$',
                              (LAB / 'scripts/image-versions.sh').read_text(), re.M))
    refs = {}
    all_nodes = [f'{site}-control-plane' for site in SITES] + FABRIC
    def add(found, nodes):
        for image in found:
            refs.setdefault(image, set()).update(nodes)
    paths = [
        (LAB / 'resources/tenants', LOCAL['galactic-cni:latest']),
        (REPO / 'config/galactic-edge/tun-device-plugin', EDGE[:2]),
        (REPO / 'config/bmp-collector', ['iad-worker3']),
    ]
    add((image for image in yaml_images(
        (REPO / 'config/fabric-router/daemonset.yaml').read_text())
         if not image.startswith('ghcr.io/datum-cloud/fabric-router:')), FABRIC)
    for root, nodes in paths:
        for path in root.rglob('*.yaml'):
            add(yaml_images(path.read_text()), nodes)
    charts = [
        ('cilium', versions['CILIUM_RELEASE'], 'https://helm.cilium.io'),
        ('cert-manager', versions['CERT_MANAGER_VERSION'], 'oci://quay.io/jetstack/charts/cert-manager'),
        ('cert-manager-csi-driver', versions['CSI_DRIVER_VERSION'],
         'oci://quay.io/jetstack/charts/cert-manager-csi-driver'),
    ]
    for name, version, source in charts:
        candidates = [CACHE / f'{name}-{v}.tgz' for v in (version, version.lstrip('v'))]
        target = next((path for path in candidates if path.exists()), None)
        if target is None:
            args = ['helm', 'pull', source if source.startswith('oci:') else name,
                    '--version', version, '--destination', str(CACHE)]
            if not source.startswith('oci:'):
                args += ['--repo', source]
            run(*args)
            target = next((path for path in candidates if path.exists()), None)
            if target is None:
                raise RuntimeError(f'Helm did not write the requested chart: {name} {version}')
        args = ['helm', 'template', name, str(target)]
        if name == 'cert-manager-csi-driver':
            args += ['--set', 'tolerations[0].operator=Exists']
        for image, nodes in chart_placements(run(*args, capture=True), all_nodes):
            add([image], nodes)
    multus = CACHE / f'multus-{versions["MULTUS_VERSION"]}.yaml'
    if not multus.exists():
        url = ('https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/refs/tags/'
               f'{versions["MULTUS_VERSION"]}/deployments/multus-daemonset-thick.yml')
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        multus.write_bytes(data)
    add(yaml_images(multus.read_text()), all_nodes)
    return {image: sorted(nodes) for image, nodes in sorted(refs.items())}


def registry_volume():
    result = subprocess.run(['docker', 'volume', 'inspect', REGISTRY], capture_output=True, text=True)
    if result.returncode == 0:
        volume = json.loads(result.stdout)[0]
        if (volume.get('Labels') or {}).get(LABEL) != 'true':
            raise RuntimeError('Registry volume is not lab-owned; refusing to reuse it')
    else:
        run('docker', 'volume', 'create', '--label', f'{LABEL}=true', REGISTRY)


def clean():
    result = subprocess.run(['docker', 'container', 'inspect', REGISTRY], capture_output=True, text=True)
    if result.returncode == 0:
        container = json.loads(result.stdout)[0]
        if (container['Config'].get('Labels') or {}).get(LABEL) != 'true':
            raise RuntimeError('Registry container is not lab-owned; refusing to remove it')
        run('docker', 'rm', '-f', REGISTRY)
    result = subprocess.run(['docker', 'volume', 'inspect', REGISTRY], capture_output=True, text=True)
    if result.returncode == 0:
        volume = json.loads(result.stdout)[0]
        if (volume.get('Labels') or {}).get(LABEL) != 'true':
            raise RuntimeError('Registry volume is not lab-owned; refusing to remove it')
        run('docker', 'volume', 'rm', REGISTRY)


def start_registry():
    registry_volume()
    result = subprocess.run(['docker', 'container', 'inspect', REGISTRY], capture_output=True, text=True)
    if result.returncode == 0:
        container = json.loads(result.stdout)[0]
        if (container['Config'].get('Labels') or {}).get(LABEL) != 'true':
            raise RuntimeError('Registry name belongs to another container; refusing to replace it')
        if not container['State']['Running']:
            run('docker', 'start', REGISTRY)
    else:
        run('docker', 'run', '-d', '--name', REGISTRY, '--restart=unless-stopped',
            '--label', f'{LABEL}=true', '-p', '127.0.0.1:5001:5000',
            '-v', 'galactic-lab-registry:/var/lib/registry', 'registry:3.0.0')
    for _ in range(30):
        try:
            with urllib.request.urlopen(f'http://{HOST}/v2/', timeout=2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError('Local registry did not become ready')


def publish():
    CACHE.mkdir(parents=True, exist_ok=True)
    start_registry()
    records = []
    # Publish once per image. Node pulls reuse registry layers; no per-node tar archives.
    for image, nodes in LOCAL.items():
        dest = f'{HOST}/lab/{image}'
        local = json.loads(run('docker', 'image', 'inspect', image, capture=True))[0]
        image_id = local['Id']
        platform = f'{local["Os"]}/{local["Architecture"]}'
        run('docker', 'tag', image, dest)
        run('docker', 'push', dest)
        digest = crane('digest', '--insecure', dest)
        config = json.loads(crane('manifest', '--insecure', '--platform', platform, dest))['config']['digest']
        # Docker's containerd image store reports the index digest as Id;
        # the classic store reports the platform config digest instead.
        if image_id not in (digest, config):
            raise RuntimeError(f'Image digest changed during publication: {image}')
        records.append(dict(image=canonical(image), path='lab/' + image.split(':')[0],
                            digest=digest, config=config, docker_id=image_id, nodes=nodes))
    for image, nodes in external_images().items():
        image = canonical(image)
        # Resolve mutable tags once per deployment; copying a digest closes the tag race.
        digest = crane('digest', image)
        source = image.split('@')[0] + '@' + digest
        path = 'external/' + hashlib.sha256(image.encode()).hexdigest()[:24]
        dest = f'{HOST}/{path}:cached'
        crane('copy', source, dest)
        if crane('digest', '--insecure', dest) != digest:
            raise RuntimeError(f'External image digest changed: {image}')
        config = json.loads(crane('manifest', '--platform', native_platform(), source))['config']['digest']
        records.append(dict(image=image, path=path, digest=digest, config=config, nodes=nodes))
    target = CACHE / 'inventory.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(records, indent=2) + '\n')
    temporary.replace(target)


def image_matches(node, reference, config):
    if not config:
        return False
    result = subprocess.run(['docker', 'exec', node, 'crictl', 'inspecti', reference],
                            capture_output=True, text=True)
    return result.returncode == 0 and json.loads(result.stdout)['status']['id'] == config


def wait_for_image(node, reference, config=None):
    # CRI learns ctr tag updates asynchronously. Wait until kubelet sees the
    # expected image, including a replacement of an existing mutable tag.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = subprocess.run(['docker', 'exec', node, 'crictl', 'inspecti', reference],
                                capture_output=True, text=True)
        if result.returncode == 0:
            inspected = json.loads(result.stdout)
            if not config or inspected['status']['id'] == config:
                return
        time.sleep(0.25)
    raise RuntimeError(f'{node}: CRI did not expose the expected image within 30s: {reference}')


def pull_node(node, records):
    started = time.monotonic()
    print(f'Loading images on {node}', flush=True)
    for record in records:
        if node not in record['nodes']:
            continue
        reference = canonical(record['image'])
        if image_matches(node, reference, record.get('config')):
            continue
        source = f'{NODE_HOST}/{record["path"]}@{record["digest"]}'
        run('docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'pull',
            '--local', '--plain-http', '--skip-metadata', source)
        run('docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'tag',
            '--force', source, reference)
        wait_for_image(node, reference, record.get('config'))
    # Canonical workload tags retain the images. Drop transport references,
    # including older digests, so containerd can reclaim superseded layers.
    references = run('docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'ls', '-q', capture=True)
    transport = [ref for ref in references.splitlines()
                 if ref.startswith((f'{NODE_HOST}/lab/', f'{NODE_HOST}/external/'))]
    if transport:
        run('docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'rm', *transport)
    print(f'Loaded {node} in {time.monotonic()-started:.3f}s', flush=True)


def load():
    records = json.loads((CACHE / 'inventory.json').read_text())
    container = json.loads(run('docker', 'container', 'inspect', REGISTRY, capture=True))[0]
    if 'kind' not in container['NetworkSettings']['Networks']:
        run('docker', 'network', 'connect', 'kind', REGISTRY)
    nodes = sorted({node for record in records for node in record['nodes']})
    # Bound unpack pressure on the host disk independently of site concurrency.
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(pull_node, node, records) for node in nodes]
        for future in futures:
            future.result()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('publish', 'load', 'clean'))
    args = parser.parse_args()
    {'publish': publish, 'load': load, 'clean': clean}[args.action]()
