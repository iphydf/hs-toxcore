# Hatter and the nixpkgs it's built and tested with. Our fixes are in the
# workspace clone until they're merged.
let
  src = builtins.path {
    name = "hatter";
    path = ../../../third_party/hatter;
    filter = path: _: baseNameOf path != ".git";
  };
  sources = import "${src}/npins";
in
{
  inherit src sources;
  pkgs = import sources.nixpkgs { };
  # Without the files only nix and Android read.
  app = pkgs: pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../toxcore-android.cabal
      ../src
      ../test
    ];
  };
}
