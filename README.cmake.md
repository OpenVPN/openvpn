OpenVPN Builds with CMake
=========================

For Windows builds we do not use the autotools-based buildsystem that we use
for our Unix-like (Linux, BSDs, macOS, etc.) builds. Instead we added a
separate (CMake)[https://cmake.org/]-based buildsystem.

This buildsystem supports building for Windows both with MSVC (i.e. Visual
Studio) and MinGW. MinGW builds are also supported as cross-compile
from Linux.

The official builds, which are also available as CMake presets (see
`cmake --list-presets` and `CMakePresets.json`) all use
(VCPKG)[https://github.com/microsoft/vcpkg/#vcpkg-overview] for dependency
management. This allows us to do proper supply-chain management and
also makes cross-building with MinGW on Linux much simpler. However,
builds are also possible by providing the build dependencies manually,
but that might require specifying more information to CMake.

You need at least CMake version 3.21 or newer for the `CMakePreset.json`
file to be supported. Manual builds might be possible with older CMake
versions, see `cmake_minimum_required` in `CMakeLists.txt`.

If you're looking to build the full Windows installer MSI, take a look
at https://github.com/OpenVPN/openvpn-build.git .

MSVC builds
-----------

The following tools are expected to be present on the system, you
can install them with a package manager of your choice (e.g.
chocolatey, winget) or manually:

* CMake (>= 3.21)
* Git
* Python (3.x), plus the Python module `docutils`
* Visual Studion 17 (2022), C/C++ Environment

For example, to prepare the required tools with chocolatey, you
can use the following commands (Powershell):

    # Installing Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    & choco.exe install -y git --params "/GitAndUnixToolsOnPath"
    & choco.exe install -y python
    & python.exe -m ensurepip
    & python.exe -m pip install --upgrade pip
    & python.exe -m pip install docutils
    & choco.exe install -y cmake --installargs 'ADD_CMAKE_TO_PATH=System'
    & choco.exe install -y "visualstudio2022buildtools"
    & choco.exe install -y "visualstudio2022-workload-vctools" --params "--add Microsoft.VisualStudio.Component.UWP.VC.ARM64 --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.VC.ATL.Spectre --add Microsoft.VisualStudio.Component.VC.ATLMFC.Spectre --add Microsoft.VisualStudio.Component.VC.ATL.ARM64.Spectre --add Microsoft.VisualStudio.Component.VC.MFC.ARM64.Spectre --add Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre --quiet"
    & choco.exe install -y windows-sdk-10-version-2004-windbg

One or more restarts of Powershell might be required to pick up new additions
to `PATH` between steps. A Windows restart is probably required after
installing Visual Studio before being able to use it.
You can find the exact commands we use to set up the community build machines
at https://github.com/OpenVPN/openvpn-buildbot/blob/master/jenkins/windows-server/msibuild.pkr.hcl

To do a default build, assuming you are in a MSVC 17 2022 environment:

    mkdir C:\OpenVPN
    cd C:\OpenVPN
    git clone https://github.com/microsoft/vcpkg.git
    git clone https://github.com/OpenVPN/openvpn.git
    set VCPKG_ROOT=C:\OpenVPN\vcpkg
    cd openvpn
    cmake --preset win-amd64-release
    cmake --build --preset win-amd64-release
    ctest --preset win-amd64-release

When using the presets, the build directory is
`out/build/<preset-name>/`, you can find the output files there.
No install support is provided directly in OpenVPN build, take a look
at https://github.com/OpenVPN/openvpn-build.git instead.

MinGW builds (cross-compile on Linux)
-------------------------------------

To build the Windows executables on a Linux system:

    # install mingw with the package manager of your choice, e.g.
    sudo apt-get install -y mingw-w64
    # in addition to mingw we also need a toolchain for host builds, e.g.
    sudo apt-get install -y build-essential
    # minimum required tools for vcpkg bootstrap: curl, zip, unzip, tar, e.g.
    sudo apt-get install -y curl zip unzip tar
    # additionally vcpkg requires powershell when building Windows binaries.
    # See https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux
    # e.g.
    sudo apt-get install -y wget apt-transport-https software-properties-common
    wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
    sudo dpkg -i packages-microsoft-prod.deb
    sudo apt-get update
    sudo apt-get install -y powershell
    # minimum required tools for build: cmake, docutils, git, ninja,
    # pkg-config, python e.g.
    sudo apt-get install -y cmake git ninja-build pkg-config python3 python3-docutils
    # additionally required to build pkcs11-helper: automake, autoconf,
    # man2html, e.g.
    sudo apt-get install -y automake autoconf man2html-base
    mkdir mingw
    cd mingw
    git clone https://github.com/microsoft/vcpkg.git
    git clone https://github.com/OpenVPN/openvpn.git
    export VCPKG_ROOT=$PWD/vcpkg
    cd openvpn
    # requires CMake 3.21 or newer
    cmake --preset mingw-x64
    cmake --build --preset mingw-x64
    # unit tests are built, but no testPreset is provided. You need to copy
    # them to a Windows system manually

The instructions have been verified on a Ubuntu 22.04 LTS system in a
bash shell, and might need adaptions to other Linux distributions/versions.

Note that the MinGW preset builds use the `Ninja multi-config` generator, so
if you want to build the Debug binaries, use

    cmake --build --preset mingw-x64 --config Debug

The default build is equivalent to specifying `--config Release`.

When using the presets, the build directory is
`out/build/mingw/<arch>`, you can find the actual output files in
sub-directories called `<buildtype>`.
No install support is provided directly in OpenVPN build, take a look
at https://github.com/OpenVPN/openvpn-build.git instead.

Unsupported builds
------------------

The CMake buildsystem also supports builds on Unix-like platforms. These builds
are sometimes useful for OpenVPN developers (e.g. when they use IDEs with
integrated CMake support). However, they are not officially supported, do not
include any install support and should not be used to distribute/package
OpenVPN. To emphasize this fact, you need to specify `-DUNSUPPORTED_BUILDS=ON`
to cmake to be able to use these builds.

The `unix-native` CMake preset is available for these builds. This preset does
not require VCPKG and instead assumes all build-dependencies are provided by
the system natively.
