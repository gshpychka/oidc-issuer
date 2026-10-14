{
  description = "Short-lived OIDC tokens for a NixOS machine's local users and services, for AWS STS federation";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # shared by `nix fmt` and the treefmt check
      formatTools =
        pkgs: with pkgs; [
          treefmt
          nixfmt
          ruff
          taplo
          opentofu
        ];
    in
    {
      nixosModules = {
        simple = ./modules/simple;
        spire = ./modules/spire.nix;
        default.imports = [
          self.nixosModules.simple
          self.nixosModules.spire
        ];
      };

      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./package { };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.opentofu
            pkgs.cloudflared
            pkgs.awscli2
          ]
          ++ formatTools pkgs;
        };
      });

      formatter = forAllSystems (
        pkgs:
        pkgs.writeShellApplication {
          name = "treefmt";
          runtimeInputs = formatTools pkgs;
          text = ''exec treefmt "$@"'';
        }
      );

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        # copy out of the read-only store so treefmt can rewrite in place,
        # then fail if anything changed
        treefmt = pkgs.runCommand "check-treefmt" { nativeBuildInputs = formatTools pkgs; } ''
          cp -r --no-preserve=mode,ownership ${self} src
          cd src
          HOME=$TMPDIR treefmt --no-cache --fail-on-change --tree-root .
          touch $out
        '';
        ruff = pkgs.runCommand "check-ruff" { nativeBuildInputs = [ pkgs.ruff ]; } ''
          cd ${self}
          ruff check --no-cache .
          touch $out
        '';
      });
    };
}
