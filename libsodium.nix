{ lib, stdenv, fetchFromGitHub, autoreconfHook }:

stdenv.mkDerivation rec {
  name = "libsodium-1.0.18-vrf";

  src = fetchFromGitHub {
    owner = "input-output-hk";
    repo = "libsodium";
    rev = "66f017f16633f2060db25e17c170c2afa0f2a8a1";
    sha256 = "12g2wz3gyi69d87nipzqnq4xc6nky3xbmi2i2pb2hflddq8ck72f";
  };

  nativeBuildInputs = [ autoreconfHook ];

  configureFlags = "--enable-static --disable-shared --disable-pie --disable-ssp";
  #configureFlags = "--disable-static --enable-shared --disable-pie --disable-ssp";

  outputs = [ "out" "dev" ];

  hardeningEnable = [ "pic" ];
  hardeningDisable = [ "pie" "stackprotector" ];


  # separateDebugInfo = stdenv.isLinux && stdenv.hostPlatform.libc != "musl";

  enableParallelBuilding = true;

  doCheck = true;

  meta = {
    description = "A modern and easy-to-use crypto library";
    homepage = "http://doc.libsodium.org/";
    # license = licenses.isc;
    maintainers = [ "tdammers" "nclarke" ];
    platforms = lib.platforms.all;
  };
}
