{
  lib,
  craneLib,
}:
let
  root = ../.;

  sources = craneLib.fileset.commonCargoSources root;

  args = {
    src = lib.fileset.toSource {
      inherit root;
      fileset = sources;
    };
    strictDeps = true;
  };

  cargoVendorDir = craneLib.vendorCargoDeps args;

  # the dependency build sees gjallar at version 0.0.0, so a release that only
  # bumps the version reuses the cached dependency build
  locked = builtins.readFile ../Cargo.lock;
  workspace = builtins.filter (package: !(package ? source)) (builtins.fromTOML locked).package;
  entry = name: version: ''
    name = "${name}"
    version = "${version}"
  '';
  unversionedLock =
    let
      versioned = map (package: entry package.name package.version) workspace;
      unversioned = map (package: entry package.name "0.0.0") workspace;
    in
    assert lib.assertMsg (lib.all (
      text: builtins.replaceStrings [ text ] [ "" ] locked != locked
    ) versioned) "Cargo.lock lays out gjallar's own entry differently than expected";
    builtins.toFile "Cargo.lock" (builtins.replaceStrings versioned unversioned locked);

  # its name, version and vendored sources are given, so crane never reads
  # this generated source while evaluating. every feature is built, so the
  # checks with and without the client share it
  cargoArtifacts = craneLib.buildDepsOnly (
    removeAttrs args [ "src" ]
    // {
      inherit cargoVendorDir;
      pname = "gjallar";
      version = "0.0.0";
      cargoExtraArgs = "--locked --all-features";
      dummySrc = craneLib.mkDummySrc (
        args
        // {
          src = lib.fileset.toSource {
            inherit root;
            fileset = lib.fileset.difference sources ../Cargo.lock;
          };
          cargoLock = unversionedLock;
          cleanCargoTomlFilter =
            path:
            craneLib.filters.cargoTomlDefault path
            &&
              path != [
                "package"
                "version"
              ];
        }
      );
    }
  );

  checkArgs = args // {
    inherit cargoArtifacts;
  };
in
craneLib.buildPackage (
  checkArgs
  // {
    cargoExtraArgs = "--locked --all-features";

    # the tests run once per feature set, in `passthru.checks`
    doCheck = false;

    passthru.checks = {
      test = craneLib.cargoTest checkArgs;
      # the client's tests talk to a fake push service on loopback
      test-client = craneLib.cargoTest (
        checkArgs
        // {
          cargoTestExtraArgs = "--all-features";
          __darwinAllowLocalNetworking = true;
        }
      );
      clippy = craneLib.cargoClippy (
        checkArgs
        // {
          cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
        }
      );
      doc = craneLib.cargoDoc (
        checkArgs
        // {
          cargoDocExtraArgs = "--no-deps --all-features";
          RUSTDOCFLAGS = "--deny warnings";
        }
      );
      fmt = craneLib.cargoFmt { inherit (args) src; };
    };

    meta = {
      description = "Web Push for Rust servers: RFC 8291 encryption, VAPID and Declarative Web Push";
      homepage = "https://github.com/GustavoWidman/gjallar";
      license = lib.licenses.mit;
    };
  }
)
