## Contributing and local builds

- Tooling: Dart 3.10+ / Flutter 3.38+ with Native Assets; standard C build toolchain (perl + make/clang on macOS/Linux; MSVC + perl + jom on Windows—hook can download perl/jom if missing).
- Clone with submodules: `git clone --recurse-submodules <repo>` (or `git submodule update --init` after cloning).
- Install deps: `dart pub get`.
- Regenerate bindings after updating headers: `dart run tool/ffigen.dart`.
- Build the native assets: run the app (`dart run`) and the hook compiles OpenSSL (first build ~1 minute).
- Tests: `dart test`.
