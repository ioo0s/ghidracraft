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

### User Scripts and Extensions
Ghidra installations support users writing custom scripts and extensions via the *GhidraDev* plugin 
for Eclipse.  The plugin and its corresponding instructions can be found within a Ghidra release at
`Extensions/Eclipse/GhidraDev/`.

### Advanced Development
To develop the Ghidra tool itself, it is highly recommended to use Eclipse, which the Ghidra 
development process has been highly customized for.

##### Install build and development tools:
* Follow the above build instructions so the build completes without errors
* Install [Eclipse IDE for Java Developers][eclipse]

##### Prepare the development environment (Linux-only, see **NOTE** for Windows/macOS):
``` 
$ gradle prepdev eclipse buildNatives_linux64
```
**NOTE:** If you are on a Windows or macOS platform, change `buildNatives_linux64` to 
`buildNatives_win64` or `gradle buildNatives_osx64`. 

##### Import Ghidra projects into Eclipse:
* *File* -> *Import...*
* *General* | *Existing Projects into Workspace*
* Select root directory to be your downloaded or cloned ghidra source repository
* Check *Search for nested projects*
* Click *Finish*

When Eclipse finishes building the projects, Ghidra can be launched and debugged with the provided
**Ghidra** Eclipse *run configuration*.

For more detailed information on developing Ghidra, please read the [Developer Guide][devguide]. 

## Contribute
If you would like to contribute bug fixes, improvements, and new features back to Ghidra, please 
take a look at our [Contributor Guide][contrib] to see how you can participate in this open 
source project.


[nsa]: https://www.nsa.gov
[contrib]: CONTRIBUTING.md
[devguide]: DevGuide.md
[career]: https://www.intelligencecareers.gov/nsa
[project]: https://www.ghidra-sre.org/
[jdk11]: https://adoptium.net/releases.html?variant=openjdk11&jvmVariant=hotspot
[gradle]: https://gradle.org/releases/
[vs]: https://visualstudio.microsoft.com/vs/community/
[eclipse]: https://www.eclipse.org/downloads/packages/
[master]: https://github.com/NationalSecurityAgency/ghidra/archive/refs/heads/master.zip
