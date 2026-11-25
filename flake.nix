{
  description = "Keep automations' cookies fresh: a browser extension pushes selected cookies, end-to-end encrypted, through a relay you host.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = (lib.importTOML ./Cargo.toml).workspace.package.version;

      rustSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          ./crates
          ./testdata
        ];
      };

      crate =
        pkgs:
        {
          pname,
          description,
          mainProgram,
        }:
        pkgs.rustPlatform.buildRustPackage {
          inherit pname version;
          src = rustSrc;
          cargoLock.lockFile = ./Cargo.lock;
          # nixpkgs' cargo hooks link the system SQLite instead of the relay's bundled copy.
          buildInputs = [ pkgs.sqlite ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          cargoBuildFlags = [
            "-p"
            pname
          ];
          # The tests run an in-process relay over loopback HTTP; `just test` runs them.
          doCheck = false;
          meta = {
            inherit description mainProgram;
            license = lib.licenses.mit;
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        relay = crate pkgs {
          pname = "cookie-communism-relay";
          description = "cookie-communism relay: stores encrypted cookie envelopes between browsers and consumers";
          mainProgram = "cookie-communism-relay";
        };

        ccom = crate pkgs {
          pname = "ccom";
          description = "cookie-communism consumer CLI: keeps a Netscape cookies.txt current";
          mainProgram = "ccom";
        };

        # Needs the FDL submodule in the source: build it as `.?submodules=1#extension`, or take
        # this flake as a `git+…?submodules=1` input.
        # Unsigned builds for Firefox and Chrome: $out/firefox.zip and $out/chrome.zip, and each
        # unpacked in $out/firefox and $out/chrome for loading from a directory.
        extension = pkgs.buildNpmPackage {
          pname = "cookie-communism-extension";
          inherit version;
          src = lib.fileset.toSource {
            root = ./extension;
            fileset = lib.fileset.unions [
              ./extension/package.json
              ./extension/package-lock.json
              ./extension/build.mjs
              ./extension/tsconfig.json
              ./extension/src
              ./extension/assets
              ./extension/vendor/fdl/packages/css
            ];
          };
          npmDepsHash = "sha256-b+R8i3OTse/HXzzFZfWtVMJfSiV+zPQvQ+1mLxvW4Uc=";
          nativeBuildInputs = [ pkgs.zip ];
          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist/firefox dist/chrome dist/firefox.zip dist/chrome.zip $out/
            runHook postInstall
          '';
          meta = {
            description = "cookie-communism browser extension for Firefox and Chrome";
            license = lib.licenses.mit;
          };
        };

        default = pkgs.symlinkJoin {
          name = "cookie-communism-${version}";
          paths = [
            relay
            ccom
          ];
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.nodejs
            pkgs.just
            pkgs.zip
          ];
        };
      });
    };
}
