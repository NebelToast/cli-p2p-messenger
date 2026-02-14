{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    naersk, # 
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [rust-overlay.overlays.default];
    };
    
    toolchain = pkgs.rust-bin.fromRustupToolchainFile ./toolchain.toml;

    naersk-lib = pkgs.callPackage naersk {
      cargo = toolchain;
      rustc = toolchain;
    };
  in {
    packages.${system}.default = naersk-lib.buildPackage {
      root = ./.;

    };

    devShells.${system}.default = pkgs.mkShell {
      packages = [
        toolchain
        pkgs.rust-analyzer-unwrapped
        pkgs.cargo-nextest
        pkgs.cargo-llvm-cov
        pkgs.git-cliff
      ];

      RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
    };
  };
}