/// Native Assets build hook for BoringSSL.
///
/// Builds libboringssl_dart.so from the BoringSSL source bundled in the
/// webcrypto pub-cache package. No download required — the source ships with
/// webcrypto and includes pre-generated platform assembly files (no Go needed).
///
/// If webcrypto is not in pub cache, add it:
///   dart pub cache add webcrypto --version 0.5.8
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const _libName = 'boringssl_dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    // Only Linux and macOS are supported (Windows would need different approach).
    final os = input.config.code.targetOS;
    if (os != OS.linux && os != OS.macOS) {
      print('BoringSSL: skipping unsupported OS $os');
      return;
    }

    final sharedDir  = input.outputDirectoryShared;
    final libName    = _libFileName(os);
    final libOutPath = sharedDir.resolve(libName);

    // Skip rebuild if library is already in the shared output directory.
    if (File(libOutPath.toFilePath()).existsSync()) {
      _addAsset(output, input, libOutPath, os);
      return;
    }

    // Locate webcrypto's BoringSSL sources in pub cache.
    final boringSslSrc = _findBoringSslSrc();
    if (boringSslSrc == null) {
      throw StateError(
        'BoringSSL source not found in pub cache.\n'
        'Add it with: dart pub cache add webcrypto --version 0.5.8\n'
        'Then re-run: dart pub get',
      );
    }
    print('BoringSSL: using source from $boringSslSrc');

    // Write a minimal CMakeLists.txt into the output working directory.
    final workDir   = input.outputDirectory;
    final cmakeFile = File(workDir.resolve('CMakeLists.txt').toFilePath());
    cmakeFile.writeAsStringSync(_cmakeLists(boringSslSrc, os));

    final buildDir = workDir.resolve('cmake_build/').toFilePath();
    Directory(buildDir).createSync(recursive: true);

    // Configure.
    await _run('cmake', [
      '-S', workDir.toFilePath(),
      '-B', buildDir,
      '-DCMAKE_BUILD_TYPE=Release',
    ]);

    // Build.
    await _run('cmake', ['--build', buildDir, '--parallel']);

    // Copy to the shared (cached) output directory.
    final builtLib = File('$buildDir/$libName');
    if (!builtLib.existsSync()) {
      throw StateError('BoringSSL build produced no output at ${builtLib.path}');
    }
    await Directory(sharedDir.toFilePath()).create(recursive: true);
    await builtLib.copy(libOutPath.toFilePath());

    _addAsset(output, input, libOutPath, os);
  });
}

void _addAsset(BuildOutputBuilder output, BuildInput input, Uri libPath, OS os) {
  output.assets.code.add(CodeAsset(
    package: input.packageName,
    name: 'src/boringssl.dart',
    linkMode: DynamicLoadingBundled(),
    file: libPath,
  ));
}

String _libFileName(OS os) {
  if (os == OS.macOS) return 'lib$_libName.dylib';
  if (os == OS.windows) return '$_libName.dll';
  return 'lib$_libName.so';
}

/// Find the newest webcrypto version in pub cache.
String? _findBoringSslSrc() {
  final pubCache = Platform.environment['PUB_CACHE'] ??
      '${Platform.environment['HOME']}/.pub-cache';
  final pubDevDir = Directory('$pubCache/hosted/pub.dev');
  if (!pubDevDir.existsSync()) return null;

  final candidates = pubDevDir.listSync()
      .whereType<Directory>()
      .where((d) => d.path.contains('/webcrypto-'))
      .map((d) => '${d.path}/third_party/boringssl')
      .where((p) => Directory(p).existsSync())
      .toList()
    ..sort();
  return candidates.isEmpty ? null : candidates.last;
}

/// Generate a CMakeLists.txt that builds libboringssl_dart from [srcDir].
String _cmakeLists(String srcDir, OS os) {
  // Trailing slash required by sources.cmake ${BORINGSSL_ROOT} references.
  final root = srcDir.endsWith('/') ? srcDir : '$srcDir/';
  final platform = os == OS.macOS ? 'apple' : 'linux';

  return '''
cmake_minimum_required(VERSION 3.6.0)
project(boringssl_dart LANGUAGES C ASM)
enable_language(ASM)

set(BORINGSSL_ROOT "$root")
include("\${BORINGSSL_ROOT}sources.cmake")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
  set(ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
  set(ARCH "aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
  set(ARCH "arm")
else()
  set(ARCH "generic")
endif()

set(PLATFORM "$platform")
if(NOT DEFINED crypto_sources_\${PLATFORM}_\${ARCH})
  add_definitions(-DOPENSSL_NO_ASM)
  set(crypto_sources_\${PLATFORM}_\${ARCH} "")
endif()

add_library(boringssl_dart SHARED
  \${crypto_sources}
  \${crypto_sources_\${PLATFORM}_\${ARCH}}
)

target_include_directories(boringssl_dart PRIVATE "\${BORINGSSL_ROOT}src/include/")
set_target_properties(boringssl_dart PROPERTIES C_VISIBILITY_PRESET default LINKER_LANGUAGE C)
target_compile_options(boringssl_dart PRIVATE -O2 -fPIC)
''';
}

Future<void> _run(String exe, List<String> args) async {
  final result = await Process.run(exe, args, includeParentEnvironment: true);
  if (result.stdout.toString().isNotEmpty) print(result.stdout);
  if (result.stderr.toString().isNotEmpty) print(result.stderr);
  if (result.exitCode != 0) {
    throw ProcessException(exe, args, result.stderr.toString(), result.exitCode);
  }
}
