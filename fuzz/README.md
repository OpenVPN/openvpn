# OpenVPN fuzzing harnesses

## How to build
```
git clone git@github.com:google/oss-fuzz
cd oss-fuzz
python3 infra_helpers.py build_fuzzers openvpn
ls -l ./build/out/openvpn | grep fuzz
```

For more configuration options such as sanitizers and fuzzers, run: ``python3 infra_helpers.py build_fuzzers --help``

## Harnesses
- `fuzz_base64.c`: Fuzzes OpenVPN base64 encode/decode functions.
- `fuzz_buffer.c`: Fuzzes buffer and string utility routines.
- `fuzz_crypto.c`:  Fuzzes key handling plus OpenVPN encrypt/decrypt paths.
- `fuzz_dhcp.c`: Fuzzes DHCP router option parsing via `dhcp_extract_router_msg`.
- `fuzz_forward.c`: Fuzzes forward path functions for incoming/outgoing tun and link processing.
- `fuzz_list.c`: Fuzzes hash/list utilities (init/add/remove/iterate) in `list.h`.
- `fuzz_misc.c`: Fuzzes env_set management and misc string helpers like `sanitize_control_message`.
- `fuzz_mroute.c`: Fuzzes multicast route parsing/helpers (`mroute_extract_*`, helper init).
- `fuzz_packet_id.c`: Fuzzes packet ID tracking, read/write, and persistence load/save.
- `fuzz_proxy.c`: Fuzzes HTTP proxy auth/setup via `establish_http_proxy_passthru`.
- `fuzz_route.c`: Fuzzes IPv4/IPv6 route option parsing and add/delete routing logic.
- `fuzz_verify_cert.c`: Fuzzes X509 parsing and TLS cert verification (`verify_cert`).
