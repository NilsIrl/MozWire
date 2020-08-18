with import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/20.03.tar.gz";
  sha256 = "0182ys095dfx02vl2a20j1hz92dx3mfgz2a6fhn31bqlp1wa8hlq";
}) {};

{
  package = rustPlatform.buildRustPackage rec {
    pname = "MozWire";
    version = "0.4.1";

    src = fetchFromGitHub {
      owner = "NilsIrl";
      repo = pname;
      rev = "v${version}";
      sha256 = "1slfb6m22vzglnrxahlhdcwzwpf3b817mskdx628s92mjzngzyih";
    };

    buildInputs = stdenv.lib.optionals stdenv.isDarwin [ darwin.Security ];

    cargoSha256 = "1lcfflblsq03l2gp9w70vbw8f9ijg9k62xpmvx2sggfbr81l2c0s";

  };
}
