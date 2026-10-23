{
  description = "eMudhra Keys classroom development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      perSystem = { pkgs, ... }: {
        formatter = pkgs.nixfmt;
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            python315
            uv
            nginx
            openssl
            direnv
            git
            ruff
          ];
          # Use the Nix interpreter, including on hosts without a system Python.
          UV_PYTHON_DOWNLOADS = "never";
          UV_PYTHON = "${pkgs.python315}/bin/python3.15";
        };
      };
    };
}
