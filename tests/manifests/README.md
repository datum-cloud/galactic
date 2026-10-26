# Manifest render fixtures

`task test:manifests` builds every kustomization here with kustomize. Each
directory under `fabric-api/` composes opt-in Components the way a cell
overlay does and must build; each directory under `invalid/` lists a
Component without the one it requires and must fail to build.
