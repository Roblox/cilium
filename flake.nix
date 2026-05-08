{
  description = "cilium dev environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    nixpkgs-tparse.url = "github:NixOS/nixpkgs/e518d4ad2bcad74f98fec028cf21ce5b1e5020dd"; #revision for tparse
    nixpkgs-ginkgo.url = "github:NixOS/nixpkgs/89f196fe781c53cb50fef61d3063fa5e8d61b6e5"; #revision for ginkgo
  };

  outputs = { self, nixpkgs, nixpkgs-tparse, nixpkgs-ginkgo }:
  let
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux for my pbp
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper to provide system-specific attributes
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
        pkgs-tp = import nixpkgs-tparse { inherit system; };
        pkgs-g = import nixpkgs-ginkgo { inherit system; };
      });
  in {
    # Development env package required.
    devShells = forAllSystems ({ pkgs, pkgs-tp, pkgs-g }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            neovim
            go # Go 1.24.4
            gotools
            llvmPackages_18.clangUseLLVM
            pkgs-g.ginkgo
            golangci-lint
            docker
            docker-compose
            python313Packages.pip
            kubernetes-helm
            kind
            kubectl
            cilium-cli
            pkgs-tp.tparse
          ];
        };
    });
  };
}
