#ifndef __COMPAT_STDBOOL_H
#define __COMPAT_STDBOOL_H

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef int bool;
#define false 0
#define true 1
#endif

#endif
