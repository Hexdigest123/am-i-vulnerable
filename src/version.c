#define _POSIX_C_SOURCE 200809L

#include "version.h"

#include <ctype.h>
#include <stddef.h>

static int order(int c) {
  if (c == '~') {
    return -1;
  }
  if (c == '\0' || isdigit(c)) {
    return 0;
  }
  if (isalpha(c)) {
    return c;
  }
  return c + 256;
}

static int verrevcmp(const char *a, const char *b) {
  while (*a != '\0' || *b != '\0') {
    int first_diff = 0;

    while ((*a != '\0' && !isdigit((unsigned char)*a)) ||
           (*b != '\0' && !isdigit((unsigned char)*b))) {
      int ac = order((unsigned char)*a);
      int bc = order((unsigned char)*b);

      if (ac != bc) {
        return ac < bc ? -1 : 1;
      }
      a++;
      b++;
    }

    while (*a == '0') {
      a++;
    }
    while (*b == '0') {
      b++;
    }
    while (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
      if (first_diff == 0) {
        first_diff = (unsigned char)*a - (unsigned char)*b;
      }
      a++;
      b++;
    }
    if (isdigit((unsigned char)*a)) {
      return 1;
    }
    if (isdigit((unsigned char)*b)) {
      return -1;
    }
    if (first_diff != 0) {
      return first_diff < 0 ? -1 : 1;
    }
  }
  return 0;
}

int version_compare(const char *a, const char *b) {
  if (a == NULL) {
    a = "";
  }
  if (b == NULL) {
    b = "";
  }
  return verrevcmp(a, b);
}
