# Ghidracraft

![logo](./logo.png)

Ghidracraft is [bincraft](https://github.com/StarCrossPortal/bincraft)'s ghidra fork.

Our goal is to:

- add features without worrying to much: Ghidra is improving, but slowly. We tend to move faster!
- tune Ghidra to be used by reverse-engineerings better: Ghidra tries hard to stay consistent. But we try to stay close to IDA users!
- modernize Ghidra: Ghidra is old and stable. But we want to go modern!

Checkout [our features](./GhidraCraftDocs/Features.md) to get an insight!

## Status

This project is still in early-development. Some of the features are already available (check out [changelog](./GhidraCraftDocs/CHANGELOG.md)) but still not bullet-proof.

However, everyone knows, the path to modern is always not bullet-proof. We will release nightly-build shortly.

Stable release might still take a really long time. We still haven't decided the way to release stable version.
##### Install build tools:
* [JDK 11 64-bit][jdk11]
* [Gradle 6 or 7][gradle]
* make, gcc, and g++ (Linux/macOS-only)
* [Microsoft Visual Studio][vs] (Windows-only)

Nightly-release only can be an option as we do encourage our user to stay at the status-of-the-art, right? Our
users are all pioneers!

## Future Plan (written in 2021-8-10)

- add nightly-release config
- continuously improve ghidra decompile result
- complete GraalVM support
- write devlopment tutorial
##### Create development build: 
```
$ gradle buildGhidra
```
The compressed development build will be located at `build/dist/`.

For more detailed information on building Ghidra, please read the [Developer Guide][devguide].  

## Develop

Checkout [Original Ghidra Dev Guide](./DevGuide.md) and [GhidraCraft Dev Guide](./GhidraCraftDocs/DevGuide.md) for more.

## Thanks

- [ghidra-builder](https://github.com/NyaMisty/ghidra-builder) which gives insight of how nightly build could be done