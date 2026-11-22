import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lifecycle = load('lab-lifecycle')
images = load('lab-images')
node_cache = load('lab-node-cache')


class ParallelTests(unittest.TestCase):
    def test_sites_overlap_and_failure_waits_for_other_sites(self):
        with tempfile.TemporaryDirectory() as directory:
            script = '''
set -euo pipefail
source "$1/lib.sh"
cd "$2"
site() {
  touch "$1.started"
  for i in {1..100}; do
    if [[ -f a.started && -f b.started ]]; then break; fi
    sleep .01
  done
  test -f a.started && test -f b.started
  if [[ "$1" == a ]]; then false; fi
  sleep .1
  touch "$1.finished"
}
parallel_sites site a b
touch must-not-run
'''
            result = subprocess.run(['bash', '-c', script, 'test', str(SCRIPTS), directory], timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((Path(directory) / 'b.finished').exists())
            self.assertFalse((Path(directory) / 'a.finished').exists())
            self.assertFalse((Path(directory) / 'must-not-run').exists())

    def test_cluster_creation_uses_distinct_kubeconfigs(self):
        with tempfile.TemporaryDirectory() as directory:
            kind = Path(directory) / 'kind'
            kind.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$LOG"\n')
            kind.chmod(0o755)
            import os
            env = {**os.environ, 'PATH': directory + ':' + os.environ['PATH'],
                   'LOG': directory + '/calls'}
            subprocess.run([str(SCRIPTS / 'deploy-clusters.sh')], env=env, check=True)
            calls = (Path(directory) / 'calls').read_text().splitlines()
            self.assertEqual(len(calls), 6)
            self.assertEqual(calls[3:], [f'export kubeconfig --name {s}' for s in lifecycle.SITES])
            for site in lifecycle.SITES:
                self.assertTrue(any(f'--name {site} ' in line and
                                    f'--kubeconfig {site}.kubeconfig' in line for line in calls))


class ResetTests(unittest.TestCase):
    def test_ownership_guard(self):
        for record in [{'owner': 'galactic-worker:node-a:1'}, {'transitioning': True}, {'pending': True}]:
            with self.subTest(record=record), self.assertRaises(RuntimeError):
                lifecycle.check_fences([record])
        lifecycle.check_fences([{'owner': 'galactic-router:node-a:1'}])

    def test_component_snapshot_excludes_status_and_server_metadata(self):
        item = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                'metadata': {'name': 'controller', 'namespace': 'galactic-system',
                             'resourceVersion': '123', 'managedFields': ['server']},
                'status': {'readyReplicas': 1}, 'spec': {'replicas': 1}}
        saved = lifecycle.component(item)
        self.assertNotIn('status', saved)
        self.assertNotIn('resourceVersion', saved['metadata'])

    def test_restore_replaces_spec_instead_of_merging_patch_fields(self):
        saved = {'components': [{'kind': 'Deployment', 'metadata': {'namespace': 'galactic-system',
                  'name': 'controller'}, 'spec': {'replicas': 1, 'template': {'spec': {'containers': []}}}}],
                 'nodes': []}
        with mock.patch.object(lifecycle, 'k') as k, mock.patch.object(lifecycle, 'ready'):
            lifecycle.restore_site('site-a', saved)
        args, kwargs = k.call_args_list[0]
        self.assertIn('--type=json', args)
        patch = json.loads(kwargs['data'])
        self.assertEqual(patch, [{'op': 'add', 'path': '/spec', 'value': saved['components'][0]['spec']}])
        self.assertIn('--wait=true', k.call_args_list[-1].args)

    def test_source_change_prevents_any_mutation(self):
        with mock.patch.object(lifecycle, 'source_hash', return_value='new'), \
                mock.patch.object(lifecycle, 'run') as run, self.assertRaises(RuntimeError):
            lifecycle.preflight({'version': 1, 'source': 'old'})
        run.assert_not_called()

    def test_failed_preflight_keeps_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            state.mkdir()
            checkpoint = state / 'baseline.json'
            checkpoint.write_text('{}')
            with mock.patch.object(lifecycle, 'STATE', state), \
                    mock.patch.object(lifecycle, 'preflight', side_effect=RuntimeError('unsupported')), \
                    mock.patch.object(lifecycle, 'run') as run, self.assertRaises(RuntimeError):
                lifecycle.lifecycle('reset', Path(directory) / 'evidence')
            self.assertTrue(checkpoint.exists())
            run.assert_not_called()

    def test_reset_restores_inventory_without_building_or_creating_clusters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            state.mkdir()
            images_dir = root / 'bin/lab-images'
            images_dir.mkdir(parents=True)
            (images_dir / 'inventory.json').write_text('["branch-image"]')
            (state / 'baseline.json').write_text(json.dumps({'images': ['baseline-image'], 'sites': {}}))
            with mock.patch.object(lifecycle, 'STATE', state), mock.patch.object(lifecycle, 'REPO', root), \
                    mock.patch.object(lifecycle, 'preflight'), mock.patch.object(lifecycle, 'parallel'), \
                    mock.patch.object(lifecycle, 'checkpoint'), mock.patch.object(lifecycle, 'run') as run:
                lifecycle.lifecycle('reset', root / 'evidence')
            tasks = [call.args[1] for call in run.call_args_list]
            self.assertNotIn('build', tasks)
            self.assertNotIn('deploy:clusters', tasks)
            self.assertNotIn('images:publish', tasks)
            self.assertEqual(tasks[-len(lifecycle.BASELINE_TASKS):], list(lifecycle.BASELINE_TASKS))
            self.assertEqual(json.loads((images_dir / 'inventory.json').read_text()), ['baseline-image'])
            self.assertFalse((state / 'baseline.json').exists())


class ImageTests(unittest.TestCase):
    def test_clean_preserves_an_unowned_container(self):
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps([{'Config': {'Labels': {}}}]))
        with mock.patch.object(images.subprocess, 'run', return_value=result), \
                mock.patch.object(images, 'run') as run, self.assertRaises(RuntimeError):
            images.clean()
        run.assert_not_called()

    def test_registry_preserves_an_unowned_volume(self):
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps([{'Labels': None}]))
        with mock.patch.object(images.subprocess, 'run', return_value=result), \
                mock.patch.object(images, 'run') as run, self.assertRaises(RuntimeError):
            images.registry_volume()
        run.assert_not_called()

    def test_canonical_references(self):
        self.assertEqual(images.canonical('fabric-router:latest'), 'docker.io/library/fabric-router:latest')
        self.assertEqual(images.canonical('example/tool:v1'), 'docker.io/example/tool:v1')
        self.assertEqual(images.canonical('ghcr.io/example/tool@sha256:abc'),
                         'ghcr.io/example/tool@sha256:abc')

    def test_digest_reference_discards_tag_like_cri(self):
        self.assertEqual(images.canonical('quay.io/example/tool:v1@sha256:abc'),
                         'quay.io/example/tool@sha256:abc')
        self.assertEqual(images.canonical('localhost:5001/tool:v1@sha256:abc'),
                         'localhost:5001/tool@sha256:abc')

    def test_extracts_init_containers_and_jobs(self):
        doc = '''apiVersion: v1
kind: List
items:
  - spec:
      template:
        spec:
          initContainers:
            - image: example/init:v1
          containers:
            - image: example/main:v1
'''
        self.assertEqual(set(images.yaml_images(doc)), {'example/init:v1', 'example/main:v1'})

    def test_waits_for_cri_visibility_and_replacement_of_old_tag(self):
        results = [subprocess.CompletedProcess([], 1, stdout=''),
                   subprocess.CompletedProcess([], 0, stdout='{"status":{"id":"old"}}'),
                   subprocess.CompletedProcess([], 0, stdout='{"status":{"id":"expected"}}')]
        with mock.patch.object(images.subprocess, 'run', side_effect=results) as run, \
                mock.patch.object(images.time, 'sleep') as sleep:
            images.wait_for_image('node-a', 'example/tool:latest', 'expected')
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_skips_only_the_expected_cached_image(self):
        records = [{'image': 'example/tool:latest', 'path': 'lab/tool',
                    'digest': 'sha256:abc', 'config': 'expected', 'nodes': ['node-a']}]
        for cached in ('expected', 'branch-image'):
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps({'status': {'id': cached}}))
            with mock.patch.object(images.subprocess, 'run', return_value=result), \
                    mock.patch.object(images, 'run') as run, mock.patch.object(images, 'wait_for_image'):
                images.pull_node('node-a', records)
            self.assertEqual(run.call_count, 0 if cached == 'expected' else 2)

    def test_chart_placement_respects_taints_without_assuming_affinity(self):
        nodes = {'compute': {'labels': {'kubernetes.io/os': 'linux'}, 'taints': []},
                 'edge': {'labels': {'kubernetes.io/os': 'linux'},
                          'taints': [{'key': 'example.com/edge', 'value': 'true', 'effect': 'NoSchedule'}]}}
        pod = {'spec': {'containers': [{'image': 'example/tool:v1'}],
                        'nodeSelector': {'kubernetes.io/os': 'linux'}}}
        with mock.patch.object(images, 'node_scheduling', return_value=nodes):
            self.assertEqual(list(images.chart_placements(json.dumps(pod), nodes)),
                             [('example/tool:v1', ['compute'])])
            pod['spec']['tolerations'] = [{'operator': 'Exists'}]
            self.assertEqual(list(images.chart_placements(json.dumps(pod), nodes)),
                             [('example/tool:v1', ['compute', 'edge'])])
            pod['spec']['nodeSelector']['kubernetes.io/os'] = 'windows'
            self.assertEqual(list(images.chart_placements(json.dumps(pod), nodes)),
                             [('example/tool:v1', [])])

    def test_cri_wait_has_a_deadline(self):
        with mock.patch.object(images.time, 'monotonic', side_effect=[0, 31]), \
                self.assertRaisesRegex(RuntimeError, 'within 30s'):
            images.wait_for_image('node-a', 'example/tool:latest')

    def test_pulls_by_digest_and_preserves_workload_reference(self):
        records = [{'image': 'ghcr.io/example/tool@sha256:abc', 'path': 'external/test',
                    'digest': 'sha256:abc', 'nodes': ['node-a']}]
        with mock.patch.object(images, 'run') as run, mock.patch.object(images, 'wait_for_image'):
            images.pull_node('node-a', records)
        self.assertIn(images.NODE_HOST + '/external/test@sha256:abc', run.call_args_list[0].args)
        self.assertEqual(run.call_args_list[1].args[-1], records[0]['image'])
        with mock.patch.object(images, 'run') as run:
            images.pull_node('node-b', records)
        run.assert_not_called()


class NodeCacheTests(unittest.TestCase):
    def test_base_identity_ignores_provenance_but_detects_filesystem_changes(self):
        info = {'Id': 'index-a', 'Config': {'Env': ['PATH=/bin']},
                'RootFS': {'Layers': ['layer-a']}, 'Os': 'linux', 'Architecture': 'amd64'}
        with mock.patch.object(node_cache, 'run', side_effect=[
                json.dumps([info]), json.dumps([{**info, 'Id': 'index-b'}]),
                json.dumps([{**info, 'RootFS': {'Layers': ['layer-b']}}])]):
            before = node_cache.base_fingerprint()
            self.assertEqual(before, node_cache.base_fingerprint())
            self.assertNotEqual(before, node_cache.base_fingerprint())

    def test_reuse_requires_clean_matching_format_and_base(self):
        good = {'version': 1, 'base': 'node-image-a', 'clean': True}
        self.assertTrue(node_cache.reusable(good, 'node-image-a'))
        for changes in ({'clean': False}, {'version': 2}, {'base': 'node-image-b'}, {'clean': 'true'}):
            self.assertFalse(node_cache.reusable({**good, **changes}, 'node-image-a'))

    def test_cache_must_be_owned_and_unmounted_before_removal(self):
        volume = {'Name': node_cache.PREFIX + 'node-a', 'Mountpoint': '/vol/cache',
                  'Labels': {node_cache.LABEL: 'true'}}
        with mock.patch.object(node_cache, 'containers', return_value=[[{'Source': '/vol/cache/data'}]]), \
                mock.patch.object(node_cache, 'run') as run, self.assertRaises(RuntimeError):
            node_cache.remove(volume)
        run.assert_not_called()
        with self.assertRaises(RuntimeError):
            node_cache.owned({**volume, 'Labels': {}})
        self.assertFalse(node_cache.mounted(volume, [[{'Source': '/vol/cache-other/data'}]]))

    def test_runtime_snapshots_must_all_be_committed(self):
        node_cache.no_writable_snapshots('KEY PARENT KIND\nsha256:layer Committed\n')
        for kind in ('Active', 'View'):
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                node_cache.no_writable_snapshots(f'KEY PARENT KIND\ncontainer layer {kind}\n')

    def test_cache_mount_cannot_replace_an_existing_store(self):
        entry = {'extraMounts': [{'hostPath': '/other', 'containerPath': '/var/lib/containerd'}]}
        with self.assertRaises(RuntimeError):
            node_cache.cache_mount(entry, '/cache/data')
        self.assertEqual(entry['extraMounts'][0]['hostPath'], '/other')

    def test_failed_cri_query_cannot_be_treated_as_empty(self):
        with mock.patch.object(node_cache, 'run', side_effect=subprocess.CalledProcessError(1, 'crictl')), \
                self.assertRaises(subprocess.CalledProcessError):
            node_cache.empty_runtime('node-a')

    def test_sandbox_stop_allows_normal_container_shutdown_time(self):
        status = json.dumps({'status': {'linux': {'namespaces': {'options': {'network': 'POD'}}}}})
        with mock.patch.object(node_cache, 'run', side_effect=['pod-a', status, None]) as run:
            node_cache.stop_pods('node-a', False)
        self.assertEqual(run.call_args.args,
                         ('docker', 'exec', 'node-a', 'crictl', '--timeout=120s', 'stopp', 'pod-a'))

    def test_runtime_files_prevent_image_only_reuse(self):
        def run(*args, **kwargs):
            if 'bash' in args:
                return '/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/pod/config.json'
            return ''
        with mock.patch.object(node_cache, 'run', side_effect=run), \
                self.assertRaisesRegex(RuntimeError, 'runtime files remain'):
            node_cache.verify_empty_runtime('node-a')

    def test_release_orders_network_teardown_before_agents_and_control_plane(self):
        names = ['site-a-worker', 'site-a-control-plane']
        events = []
        def inspect(kind, name):
            node = name.removeprefix(node_cache.PREFIX)
            if kind == 'container':
                return {'Id': node, 'Mounts': [{'Source': f'/vol/{node}/data'}]}
            return {'Name': name, 'Mountpoint': f'/vol/{node}', 'Labels': {node_cache.LABEL: 'true'}}
        with mock.patch.object(node_cache, 'nodes', return_value=[('site-a', n, {}) for n in names]), \
                mock.patch.object(node_cache, 'inspect', side_effect=inspect), \
                mock.patch.object(node_cache, 'read_state', side_effect=lambda v: {'container': v.removeprefix(node_cache.PREFIX)}), \
                mock.patch.object(node_cache, 'run'), \
                mock.patch.object(node_cache, 'stop_pods', side_effect=lambda n, host: events.append((n, host))), \
                mock.patch.object(node_cache, 'empty_runtime', side_effect=lambda n: events.append((n, 'verify'))), \
                mock.patch.object(node_cache, 'write_state') as write:
            node_cache.release()
        self.assertEqual({e[0] for e in events[:2]}, set(names))
        self.assertTrue(all(e[1] is False for e in events[:2]))
        self.assertEqual(events[2:4], [('site-a-worker', True), ('site-a-control-plane', True)])
        self.assertTrue(all(call.args[1]['clean'] for call in write.call_args_list))
        self.assertEqual(write.call_count, 2)

    def test_release_never_marks_failed_teardown_clean(self):
        volume = {'Name': node_cache.PREFIX + 'node-a', 'Mountpoint': '/vol/cache',
                  'Labels': {node_cache.LABEL: 'true'}}
        container = {'Id': 'container-a', 'Mounts': [{'Source': '/vol/cache/data'}]}
        def inspect(kind, name):
            return container if kind == 'container' else volume
        with mock.patch.object(node_cache, 'nodes', return_value=[('site-a', 'node-a', {})]), \
                mock.patch.object(node_cache, 'inspect', side_effect=inspect), \
                mock.patch.object(node_cache, 'read_state', return_value={'container': 'container-a'}), \
                mock.patch.object(node_cache, 'run'), \
                mock.patch.object(node_cache, 'empty_runtime', side_effect=RuntimeError('not empty')), \
                mock.patch.object(node_cache, 'write_state') as write, self.assertRaises(RuntimeError):
            node_cache.release()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
