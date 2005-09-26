#include <stdio.h>

int
main (int argc, char *argv[])
{
  int c;
  int enable = 1;

  while ((c = getchar()) != EOF)
    {
#if 0
      if (c == '\r')
	enable = 0;
      if (enable && c == '\n')
	putchar ('\r');
#endif
      putchar (c);
    }
  return 0;
}
