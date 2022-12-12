#!/usr/bin/env python

import argparse
import os
import platform
import subprocess
import sys

TARGETS = [
           'base64',
           'buffer',
           'dhcp',
           'forward',
           'list',
           'misc',
           'mroute',
           'mss',
           'packet_id',
           'parse_argv',
           'proxy',
           'route',
           'verify_cert',
          ]

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

def fuzz_target(target, args=[]):
    build_targets([target])
    os.makedirs(corpus_dir(target), exist_ok=True)
    os.chdir(target_dir(target, "fuzzer"))
    os.execv(target_bin_path(target, "fuzzer"),
             [target_bin_path(target, "fuzzer"), corpus_dir(target)] + args)

def generate_coverage_report(targets=TARGETS):
    """
    If OpenVPN was previously built for fuzzing run `make -C ../ clean` before and after generating coverage.
    """
    wd = os.getcwd()
    build_targets(targets, for_coverage=True)
    profraws = []
    object_args = []
    for target in targets:
        os.chdir(target_dir(target, "coverage"))
        profraws.append(target_dir(target, "coverage", "default.profraw"))
        object_args.append("-object")
        object_args.append(target_bin_path(target, "coverage"))
        subprocess.run([target_bin_path(target, "coverage"), corpus_dir(target), "-runs=0"])

    profdata = build_dir("coverage", "combined.profdata")
    subprocess.run(["llvm-profdata", "merge", "-o", profdata, "-sparse"] + profraws)
    subprocess.run(["llvm-cov", "show", "--format", "html", f"-instr-profile={profdata}",
                    "-output-dir", build_dir("coverage", "report")] + object_args)
    os.chdir(wd)

def triage_parse_argv_crashes():
    """
    Filters out false positives that are caused by calling exit.
    """
    import pwn
    target = "parse_argv"
    for filename in os.listdir(target_dir(target, "fuzzer")):
        if "crash-" in filename:
            print("Triaging", filename)
            with open(target_dir(target, "fuzzer", filename), "rb") as f:
                argv_raw = f.read()
                p = pwn.process(executable="../src/openvpn/openvpn", argv=argv_raw.split(b'\x00'))
                out = p.readall()
                if b"SIGSEGV" in out or b"smashing" or b"AddressSanitizer" in out:
                    print(pwn.hexdump(argv_raw))
                    print(out)
                    exit(1)
                p.close()

def build_openvpn(cflags):
    """
    Build OpenVPN as usual, assumes `autoconf -f -v -f` and `./configure --disable-lz4` already run.
    """
    subprocess.run(["make", "-j", "-C", "../", f"CFLAGS={cflags}"])

def build_targets(targets, for_coverage=False):
    fuzzer_flags = '-g -fsanitize=address,fuzzer-no-link'
    coverage_flags = '-g -fprofile-instr-generate -fcoverage-mapping'

    build_subdir = 'coverage' if for_coverage else 'fuzzer'
    os.makedirs(build_dir(build_subdir), exist_ok=True)

    cflags = coverage_flags if for_coverage else fuzzer_flags
    cflags += " -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
    build_openvpn(cflags)

    o_files = []
    for file in os.listdir("../src/openvpn"):
        if file.endswith(".o") and file != 'openvpn.o':
            o_files.append("../src/openvpn/" + file)
    subprocess.run(["ar", "r", build_dir(build_subdir, "libopenvpn.a")] + o_files)

    subprocess.run(["clang++", "-c", "src/fuzz_randomizer.cpp",
                    "-o", build_dir(build_subdir, "fuzz_randomizer.o")] +
                   cflags.split(' '))

    extra_libs = ["-lc++abi", "-lresolv"] if platform.system() == 'Darwin' else ['-lcap-ng']

    for target in targets:
        os.makedirs(target_dir(target, build_subdir), exist_ok=True)
        subprocess.run(["clang", "-I../src/openvpn", "-I..", "-I../src/compat", "-I../include",
                        "-lssl", "-lcrypto", "-llzo2", f"src/fuzz_{target}.c",
                        build_dir(build_subdir, "libopenvpn.a"),
                        build_dir(build_subdir, "fuzz_randomizer.o"),
                        "-o", target_bin_path(target, build_subdir),
                        "-g", "-fsanitize=address,fuzzer"] +
                       (coverage_flags.split(' ') if for_coverage else []) +
                       extra_libs)

def build_dir(subdir, file=''):
    """
    There are two build flavors that live in their own subdirs: coverage and fuzzer.
    """
    return os.path.join(BASE_DIR, "build", subdir, file)

def target_dir(target, subdir, file=''):
    return os.path.join(build_dir(subdir), f"fuzz_{target}", file)

def corpus_dir(target):
    return os.path.join(BASE_DIR, "corpus", f"fuzz_{target}")

def target_bin(target):
    return f"fuzz_{target}"

def target_bin_path(target, subdir):
    return target_dir(target, subdir, target_bin(target))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    fuzz_parser = subparsers.add_parser('fuzz')
    fuzz_parser.add_argument('target', type=str)
    fuzz_parser.add_argument('libfuzzer_args', type=str, nargs='*')
    coverage_parser = subparsers.add_parser('coverage')
    coverage_parser.add_argument('targets', type=str, nargs='*')
    coverage_parser.add_argument('--clean', action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    if args.subcommand == 'fuzz':
        # ./openvpn-fuzz.py fuzz proxy -- -fork=4 -ignore_crashes=1
        fuzz_target(args.target, args.libfuzzer_args)
    elif args.subcommand == 'coverage':
        if args.clean:
            subprocess.run(["make", "-C", "../", "clean"])

        if args.targets:
            generate_coverage_report(args.targets)
        else:
            generate_coverage_report()

        if args.clean:
            subprocess.run(["make", "-C", "../", "clean"])
    else:
        parser.print_help()
