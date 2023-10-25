{ stdenv
, lib
, gnumake
, nasm
, xxd
, makeWrapper
, coreutils
, src
}:
stdenv.mkDerivation {
  name = "l1tf-demo";

  inherit src;

  nativeBuildInputs = [
    gnumake
    nasm
    xxd
    makeWrapper
  ];

  dontConfigure = true;
  installPhase = ''
    mkdir -p $out/bin
    install -m 0755 -t $out/bin l1tf ht-siblings.sh

    wrapProgram $out/bin/ht-siblings.sh \
      --prefix PATH : ${lib.makeBinPath [ coreutils ]}
  '';

  meta = {
    description = "A demonstrator for the L1TF/Foreshadow vulnerability";
    license = lib.licenses.gpl2Only;
  };
}
