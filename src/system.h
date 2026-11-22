#ifndef SYSTEM_H
#define SYSTEM_H

#include "config.h"

#define SYSTEM_MAX_PACKAGES 4096

typedef struct Package {
  char *name;
  char *version;
} Package;

int load_packages(Config *config, Package *packages);

int update_package(Config *config, Package *package);

void cleanup_packages(Package *packages);

#endif
