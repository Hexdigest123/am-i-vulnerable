#include "config.h"
#define _POSIX_C_SOURCE 200809L

#include "system.h"
#include <stdlib.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

void load_packages(Config *config, Package *packages) {
  const char *manager = PACKAGE_MANAGER[config->platform];
  const char *arguments;
  char command[PAIR_SIZE];
  char line[PAIR_SIZE];
  FILE *pipe;
  size_t count = 0;

  packages[0].name = NULL;
  packages[0].version = NULL;

  switch (config->platform) {
  case UBUNTU:
  case DEBIAN:
    arguments = "list --installed";
    break;
  case FEDORA:
    arguments = "-q list installed";
    break;
  case ARCH:
    arguments = "-Q";
    break;
  default:
    fprintf(stderr, "cannot list packages, platform is unknown\n");
    return;
  }

  snprintf(command, sizeof(command), "%s %s", manager, arguments);

  pipe = popen(command, "r");
  if (pipe == NULL) {
    fprintf(stderr, "failed to run '%s': %s\n", command, strerror(errno));
    return;
  }

  while (count + 1 < SYSTEM_MAX_PACKAGES &&
         fgets(line, sizeof(line), pipe) != NULL) {
    char *name;
    char *separator;
    char *version;
    char *version_end;

    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0') {
      continue;
    }

    name = line;
    separator = strpbrk(line, " \t");
    if (separator == NULL) {
      continue;
    }
    *separator = '\0';

    version = separator + 1;
    while (*version == ' ' || *version == '\t') {
      version++;
    }
    version_end = strpbrk(version, " \t");
    if (version_end != NULL) {
      *version_end = '\0';
    }

    /* apt prints the suite as 'name/suite', drop it. */
    separator = strchr(name, '/');
    if (separator != NULL) {
      *separator = '\0';
    }

    packages[count].name = strdup(name);
    packages[count].version = strdup(version);
    count++;
  }

  if (pclose(pipe) == -1) {
    fprintf(stderr, "failed to finish '%s': %s\n", command, strerror(errno));
  }

  packages[count].name = NULL;
  packages[count].version = NULL;
}

void update_package(Config *config, Package *package) {
  const char *manager = PACKAGE_MANAGER[config->platform];
  const char *arguments;
  char command[PAIR_SIZE];

  switch (config->platform) {
  case UBUNTU:
  case DEBIAN:
    arguments = "install --only-upgrade -y";
    break;
  case FEDORA:
    arguments = "upgrade -y";
    break;
  case ARCH:
    arguments = "-S --noconfirm";
    break;
  default:
    fprintf(stderr, "cannot update package, platform is unknown\n");
    return;
  }

  snprintf(command, sizeof(command), "%s %s %s", manager, arguments,
           package->name);

  if (system(command) == -1) {
    fprintf(stderr, "failed to run '%s': %s\n", command, strerror(errno));
  }
}

void cleanup_packages(Package *packages) {
  for (size_t i = 0; i < SYSTEM_MAX_PACKAGES; i++) {
    if (packages[i].name != NULL) {
      free(packages[i].name);
    }
    if (packages[i].version != NULL) {
      free(packages[i].version);
    }
  }
  free(packages);
}
