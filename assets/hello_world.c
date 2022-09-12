// This is a file use to compile some of the binaries in this
// directory for testing purposes.
#include <stdio.h>

extern void say(char *name) {
  printf("Hello, %s!", name);
}
