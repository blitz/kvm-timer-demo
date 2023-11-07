{ stdenv
, lib
, gnumake
, nasm
, xxd
, coreutils
, src
}:
stdenv.mkDerivation {
  name = "kvm-timer-demo";

  inherit src;

  nativeBuildInputs = [
    gnumake
    nasm
    xxd
  ];

  dontConfigure = true;
  installPhase = ''
    mkdir -p $out/bin
    install -m 0755 -t $out/bin timer
  '';

  meta = {
    description = "KVM Userspace Prototypes: KVM Timer";
    license = lib.licenses.gpl2Only;
    mainProgram = "timer";
  };
}
