# OpenVPN Fuzzing

## Setup
The fuzzing setup is handled by Nix inside a `nix-shell` and works both on
Linux and macOS. Nix is the only dependency (https://nixos.org/download.html).

## Usage

```sh
$ nix-shell fuzz/shell.nix
$ autoreconf -i -v -f
$ ./configure --disable-lz4
$ cd fuzz
$ ./openvpn-fuzz.py fuzz base64
$ ./openvpn-fuzz.py fuzz parse_argv -- -fork=4 -ignore_crashes=1
$ ./openvpn-fuzz.py coverage base64 parse_argv # specified targets
$ ./openvpn-fuzz.py coverage # all targets
$ ./openvpn-fuzz.py coverage --clean # do make clean before and after, use if previously built for fuzzing
```
