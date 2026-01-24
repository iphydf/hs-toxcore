# The app's shared library for Android.
{ androidArch ? "aarch64" }:
let
  hatter = import ./hatter.nix;
  inherit (hatter) sources;
  lib = import "${hatter.src}/nix/lib.nix" { inherit sources androidArch; };
  hatterSrc = import "${hatter.src}/nix/hatter-src.nix" { inherit sources; };
  # Linked into the app's library (Android has no libsodium).
  androidPkgs = (import sources.nixpkgs {
    config.allowUnfree = true;
    config.android_sdk.accept_license = true;
  }).pkgsCross."${androidArch}-android-prebuilt";
  libsodium = androidPkgs.libsodium.overrideAttrs
    (old: {
      dontDisableStatic = true;
      configureFlags = (old.configureFlags or [ ]) ++ [ "--with-pic" ];
    });
  # Call codecs, static too. nixpkgs configures libvpx for Linux (that
  # toolchain can't link for Android) and adds -lpthread, which is in
  # Android's libc. Its Android target links its own programs with -static,
  # which we don't build.
  libvpx = androidPkgs.libvpx.overrideAttrs (old: {
    env = (old.env or { }) // { NIX_LDFLAGS = ""; };
    outputs = [ "out" "dev" ];
    postPatch = (old.postPatch or "") + ''
      sed -i 's/check_add_ldflags -static/true/' build/make/configure.sh
    '';
    configureFlags = map
      (f: {
        "--target=arm64-linux-gcc" = "--target=arm64-android-gcc";
        "--enable-shared" = "--disable-shared";
      }.${f} or f)
      old.configureFlags
    ++ [ "--disable-examples" "--disable-tools" "--disable-unit-tests" ];
  });
  libopus = androidPkgs.libopus.overrideAttrs (old: {
    mesonFlags = old.mesonFlags ++ [ "-Ddefault_library=static" "-Dextra-programs=disabled" "-Dtests=disabled" ];
  });
  ffmpeg = (androidPkgs.ffmpeg-headless.override {
    inherit libvpx;
    withHeadlessDeps = false;
    withSmallDeps = false;
    buildAvcodec = true;
    buildAvutil = true;
    withVpx = true;
    withStatic = true;
    withShared = false;
  }).overrideAttrs (old: {
    # MediaCodec needs ffmpeg to know it's on Android, not plain Linux.
    configureFlags = map (f: if f == "--target_os=linux" then "--target_os=android" else f) old.configureFlags
      ++ [ "--enable-pic" "--enable-jni" "--enable-mediacodec" ];
  });
  # SQLCipher instead of SQLite, so chats are encrypted at rest. The
  # amalgamation is plain C, generated on the build machine.
  sqlcipher = hatter.pkgs.sqlcipher.overrideAttrs {
    pname = "sqlcipher-amalgamation";
    outputs = [ "out" ];
    buildFlags = [ "sqlite3.c" ];
    doCheck = false;
    installPhase = ''
      mkdir -p $out
      cp sqlite3.c sqlite3.h $out/
    '';
  };
  # For SQLCipher, static like the rest. We only use libcrypto, and kernel
  # TLS doesn't build for Android.
  openssl = (androidPkgs.openssl.override { static = true; }).overrideAttrs (old: {
    configureFlags = (old.configureFlags or [ ]) ++ [ "no-ktls" "no-tests" ];
  });
  crossDeps = import "${hatter.src}/nix/cross-deps.nix" {
    inherit sources androidArch hatterSrc;
    # Without profiling, like Hatter (it would need Hatter's profiling
    # libraries otherwise).
    hpkgs = hatter.pkgs.lib.composeExtensions (import ./packages.nix hatter.pkgs)
      (self: super:
      let
        # Hash of the app code, platform files, Hatter and the workspace
        # libraries, to tell builds apart.
        version = builtins.substring 0 8 (builtins.hashString "sha256" (toString [
          (hatter.app hatter.pkgs)
          ../platform
          hatter.src
          self.toxcore.drvPath
          self.toxcore-sync.drvPath
          self.toxav.drvPath
        ]));
      in {
        saltine = super.saltine.override { inherit libsodium; };
        direct-sqlite = hatter.pkgs.haskell.lib.overrideCabal super.direct-sqlite (old: {
          postPatch = (old.postPatch or "") + ''
            cp ${sqlcipher}/sqlite3.h cbits/sqlite3.h
            { printf '%s\n' \
                '#define SQLITE_HAS_CODEC 1' \
                '#define SQLITE_EXTRA_INIT sqlcipher_extra_init' \
                '#define SQLITE_EXTRA_SHUTDOWN sqlcipher_extra_shutdown' \
                '#define SQLITE_THREADSAFE 1' \
                '#define SQLITE_TEMP_STORE 2' \
                '#define SQLCIPHER_CRYPTO_OPENSSL 1'
              cat ${sqlcipher}/sqlite3.c; } > cbits/sqlite3.c
          '';
          configureFlags = (old.configureFlags or [ ]) ++ [ "--extra-include-dirs=${openssl.dev}/include" ];
        });
        toxav = super.toxav.override {
          libavcodec = ffmpeg;
          inherit ffmpeg;
          opus = libopus;
        };
        toxcore-android = with hatter.pkgs.haskell.lib; disableLibraryProfiling (dontCheck (overrideCabal
          (self.callCabal2nix "toxcore-android" (hatter.app hatter.pkgs) { })
          (old: {
            postPatch = (old.postPatch or "") + ''
              substituteInPlace src/Tox/Android/Version.hs --replace-fail '"dev"' '"${version}"'
            '';
          })));
      });
    # Only Main.hs is built outside the package.
    consumerCabal2Nix = { mkDerivation, base, lib, toxcore-android }:
      mkDerivation {
        pname = "toxcore-android-main";
        version = "0.1.0";
        libraryHaskellDepends = [ base toxcore-android ];
        license = lib.licenses.gpl3Only;
      };
  };
in
lib.mkAndroidLib {
  inherit hatterSrc crossDeps;
  pname = "toxcore-android";
  mainModule = ../app/Main.hs;
  javaPackageName = "chat.tox.hstox";
  # Each bubble and avatar is a few native views, more than the fixed pool.
  dynamicNodePool = true;
  # Tox runs on its own threads.
  threadedRts = true;
  extraLinkObjects = [
    "${libsodium}/lib/libsodium.a"
    "${openssl.out}/lib/libcrypto.a"
    "${ffmpeg.lib or ffmpeg}/lib/libavcodec.a"
    "${ffmpeg.lib or ffmpeg}/lib/libavutil.a"
    "${libvpx}/lib/libvpx.a"
    "${libopus}/lib/libopus.a"
    "-lmediandk"
    "-landroid"
  ];
  # Hatter's sources are in the build directory, but we use it from the
  # package database.
  extraModuleCopy = ''
    rm -r Hatter.hs Hatter
  '';
}
