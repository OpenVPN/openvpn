#ifdef USE_PAM_DLOPEN
/* Dynamically load and unload the PAM library */
int dlopen_pam(const char *so);

void dlclose_pam(void);

#endif
