#ifndef NTLM_H
#define NTLM_H

#if NTLM

const char *ntlm_phase_1(const struct http_proxy_info *p, struct gc_arena *gc);

const char *ntlm_phase_3(const struct http_proxy_info *p, const char *phase_2, struct gc_arena *gc);

#endif

#endif
