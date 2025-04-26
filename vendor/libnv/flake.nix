{
  description = "Minimal Rust Development Environment";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    andoriyu = {
      url = "github:andoriyu/flakes";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        rust-overlay.follows = "rust-overlay";
        flake-utils.follows = "flake-utils";
        devshell.follows = "devshell";
      };
    };
    devshell = {
      url = "github:numtide/devshell/master";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };
  outputs =
    { self, nixpkgs, rust-overlay, flake-utils, andoriyu, devshell, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        cwd = builtins.toString ./.;
        overlays = [ devshell.overlay rust-overlay.overlay andoriyu.overlay andoriyu.overlays.rust-analyzer ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.fromRustupToolchainFile "${cwd}/rust-toolchain.toml";
      in with pkgs; {
        devShell = clangStdenv.mkDerivation rec {
        name = "rust";
        nativeBuildInputs = [
            bacon
            binutils
            cargo-cache
            cargo-deny
            cargo-diet
            cargo-expand-nightly
            cargo-outdated
            cargo-sort
            cargo-sweep
            cargo-wipe
            cargo-release
            cmake
            git-cliff
            gnumake
            pkgconfig
            rust
            rusty-man
            vagrant
            just
            zlib
        ];
        PROJECT_ROOT = builtins.toString ./.;
        RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
        };
      });
}

