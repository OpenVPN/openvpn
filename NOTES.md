# Google Patch Rewards — OpenVPN local draft notes

**Date:** 2026-09-11 (America/Chicago)  
**Do not claim yet:** need upstream merge + ≥30 days, then https://bughunters.google.com/report/patch_rewards

## Chosen target + why

- **Project:** OpenVPN (widespread VPN / tunnel daemon — packet paths on untrusted network input; Google Patch Rewards memory-safety track)
- **Upstream:** https://github.com/OpenVPN/openvpn (prefer `master`; official review via Gerrit / openvpn-devel mail — GitHub PRs are discussion-only)
- **Local clone:** `/workspace/google-patch-openvpn`
- **Branch:** `local/buffer-fbounds-safety` (from `master`)
- **Why this target:**
  1. Core packet/buffer infrastructure; `struct buffer` backs encryption, TLS, socket, and management paths that handle untrusted bytes.
  2. Clear, mergeable first-CL scope: **one** internal buffer+capacity pair — `struct buffer.data` ↔ `struct buffer.capacity` — textbook `__sized_by`, not a whole-tree sweep.
  3. Same pattern as libpng / libwebp / giflib / lz4 / zstd / libzip: **inert macros** when the flag is off; experimental Clang `-fbounds-safety` only when explicitly enabled.
  4. Stable layout preserved (no field reorder); annotation links `data` to its **capacity** (`capacity`). Field order already capacity-before-pointer.
  5. Not already done upstream (no `__sized_by` / `-fbounds-safety` in tree; no overlapping open annotation PRs on GitHub search 2026-09-11).
  6. AI CONTRIBUTING gate clear (CONTRIBUTING.rst / CODE_CHECKLIST / README / `.github` — **no AI / LLM ban**).

**Why `struct buffer.data`/`capacity` over `len` or other containers:** `capacity` is the allocated size at `*data`; `len` is the live content length and is not the correct companion for an allocation bound. Other buffer-like structs (`mbuf`, frame buffers) are natural follow-ups.

**ABI / layout note:** Field order is unchanged (`capacity` already precedes `data`). Alloc / set paths (`alloc_buf`, `alloc_buf_gc`, `clone_buf`, `buf_sub`, `buf_set_write`, `buf_set_read`) **already** assign capacity before the pointer — this CL only documents that and adds the inert annotation.

## Security benefit

`struct buffer` is the primary byte container for packet construction/parse across the data and control channels. Callers already track capacity in `capacity`, but the compiler cannot see that `data` is bounded by that field.

This draft:

1. Introduces `src/openvpn/buffer_bounds_safety.h` with `OVPN_SIZED_BY` / `OVPN_SIZED_BY_OR_NULL` / `OVPN_COUNTED_BY*` (empty by default).
2. Annotates **only** `struct buffer.data` → `OVPN_SIZED_BY_OR_NULL(capacity)` (capacity bound; `data` may be NULL after `buf_reset` / `CLEAR`).
3. Keeps existing field order. Documents that alloc/set paths already assign **capacity before pointer**.
4. Wires optional CMake `ENABLE_FBOUNDS_SAFETY` / autotools `--enable-fbounds-safety` (default **OFF**) → `-DOVPN_SUPPORT_FBOUNDS_SAFETY` + `-fbounds-safety`.

**Default builds are unchanged:** macros expand to nothing; no new runtime checks without the experimental flag. Header is internal (listed in `openvpn_SOURCES` / `SOURCE_FILES`; not a public install surface).

## Files changed

| File | Change |
|------|--------|
| `src/openvpn/buffer_bounds_safety.h` | **New** — inert / Clang bounds macros |
| `src/openvpn/buffer.h` | Include header; annotate `struct buffer.data` |
| `src/openvpn/buffer.c` | Comments: capacity-first assign already present in alloc/clone/sub |
| `src/openvpn/Makefile.am` | List new header in `openvpn_SOURCES` |
| `configure.ac` | `--enable-fbounds-safety` (default no) |
| `CMakeLists.txt` | `ENABLE_FBOUNDS_SAFETY` option OFF + apply flags to `openvpn` when ON |
| `NOTES.md` | This file |

## Verified locally 2026-09-11

| Check | Result |
|-------|--------|
| Default `ENABLE_FBOUNDS_SAFETY` / `--enable-fbounds-safety` OFF out-of-tree `./configure && make` | **PASS** (gcc; `src/openvpn/openvpn` + `buffer.o`; configure prints `ENABLE_FBOUNDS_SAFETY disabled`) |
| Inert-macro smoke (`buffer_bounds_safety.h` alone) | **PASS** |
| `ENABLE_FBOUNDS_SAFETY=ON` / `--enable-fbounds-safety` | **Not feasible on this box** — needs Clang with `-fbounds-safety` / `ptrcheck.h` |

## How to build / test

Default (macros inert — must stay green). Official Unix path:

```sh
autoreconf -vi
./configure --disable-fbounds-safety
make -j
make check
```

CMake (unsupported on Unix except with the flag; used for Windows / internal):

```sh
cmake -S . -B build -DUNSUPPORTED_BUILDS=ON -DENABLE_FBOUNDS_SAFETY=OFF
cmake --build build -j
```

With experimental bounds-safety toolchain (maintainers / CI; **not** available on this box — no Clang/`ptrcheck.h`):

```sh
./configure --enable-fbounds-safety CC=<clang-with-fbounds-safety>
make -j
# or:
cmake -S . -B build-fbs -DUNSUPPORTED_BUILDS=ON -DENABLE_FBOUNDS_SAFETY=ON \
  -DCMAKE_C_COMPILER=<clang-with-fbounds-safety>
cmake --build build-fbs -j
```

## Upstream submit plan

1. Preferred: upload to **Gerrit** https://gerrit.openvpn.net/ (see https://community.openvpn.net/Development/GerritBestPractices) **or** send `git format-patch` / `git send-email` to **openvpn-devel** https://lists.sourceforge.net/lists/listinfo/openvpn-devel
2. GitHub PRs are **discussion-only** — after ACK, patch must still go to the mailing list / Gerrit (CONTRIBUTING.rst).
3. Proposed title: `buffer: add optional -fbounds-safety annotations for struct buffer`
4. Frame as secure-by-design / Safe Buffers-style systematization of the existing data+capacity pair; cite libwebp/libpng/lz4/zstd/libzip prior art and Google Patch Rewards memory-safety goals.
5. Emphasize: default build behavior unchanged; flag OFF; no PoC / no CVE claim; layout field order unchanged; capacity-first already in alloc paths.
6. Include `Signed-off-by: Jeff <jeff@incrediblybased.co>` (CODE_CHECKLIST.md).
7. Do **not** claim on https://bughunters.google.com/report/patch_rewards until **merge + ≥30 days**.

## Follow-ups (separate CLs)

- Other buffer-like structs / frame paths as diagnostics under a real `-fbounds-safety` build dictate
- `mbuf` / multi-instance buffer pools if they expose a clear capacity companion
- Unit-test targets that compile `buffer.c` independently under the opt-in flag

## AI gate

- **CONTRIBUTING.rst** present — patch/mail/Gerrit process; **no AI / LLM ban**.
- Searched CODE_CHECKLIST.md, README, `.github/PULL_REQUEST_TEMPLATE.md`, SECURITY-related docs — **no AI / LLM / Copilot ban**.
- **AI gate: CLEAR (PASS)** (no ban found).

## Status

**LOCAL DRAFT ONLY** — commit on `local/buffer-fbounds-safety`. Do **not** push/PR from this agent run. Still **no claim** until merge + ≥30 days unreverted.
