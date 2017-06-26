OpenVPN fuzzers

Get clang:

```c
git clone https://chromium.googlesource.com/chromium/src/tools/clang
clang/scripts/update.py
```

and update your ```PATH```.

Get libFuzzer:

```c
svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
cd Fuzzer
clang++ -c -g -O2 -std=c++11 *.cpp
ar r libFuzzer.a *.o
ranlib libFuzzer.a
```

Put libFuzzer in src/openvpn

Make OpenVPN

```
autoreconf -ivf; ./configure && make -j6
```

You don't need to set ```CC``` or ```CFLAGS```; they are hard-coded in this branch.

After compiling, you can find the fuzzers in src/openvpn.
