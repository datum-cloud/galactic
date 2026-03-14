{
  description = "Galactic VPC controller development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          name = "galactic";
          packages = with pkgs; [
            go-task          # task runner used by test/e2e/Taskfile.yml
            kubernetes-helm  # helm (required by deploy-cilium)
            fluxcd           # flux CLI (required by test-infra bootstrap)
          ];
        };
      }
    );
}
