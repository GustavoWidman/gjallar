{
  description = "web push for rust servers: rfc 8291 encryption, vapid and declarative web push";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-parts.url = "github:hercules-ci/flake-parts";
    devshell.url = "github:numtide/devshell";
  };

  outputs =
    inputs@{
      flake-parts,
      crane,
      devshell,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # nixpkgs no longer evaluates for x86_64-darwin
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      imports = [
        devshell.flakeModule
      ];

      perSystem =
        { pkgs, ... }:
        let
          # nixpkgs' stable rust, which cache.nixos.org serves ready to run, for
          # builds, checks and the devshell alike
          craneLib = crane.mkLib pkgs;
          gjallar = pkgs.callPackage ./nix/package.nix { inherit craneLib; };
        in
        {
          packages.default = gjallar;

          checks = {
            inherit gjallar;
          }
          // gjallar.passthru.checks;

          devshells.default = {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer
            ];
            env = [
              {
                name = "RUST_SRC_PATH";
                value = "${pkgs.rustPlatform.rustLibSrc}";
              }
            ];

            motd = "";
          };
        };
    };
}
