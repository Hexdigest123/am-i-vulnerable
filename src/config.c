#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *PACKAGE_MANAGER[] = {
    [UBUNTU] = "apt",  [DEBIAN] = "apt",      [FEDORA] = "dnf",
    [ARCH] = "pacman", [UNKNOWN] = "unknown",
};

static void set_string(char **target, const char *value) {
  char *copy = strdup(value);

  if (copy == NULL) {
    fprintf(stderr, "failed to allocate memory: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  free(*target);
  *target = copy;
}

static Pair *init_pair_array(int size) {
  Pair *pairs = calloc((size_t)size, sizeof(*pairs));

  if (pairs == NULL) {
    fprintf(stderr, "failed to allocate memory: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < size; i++) {
    pairs[i].key = calloc(PAIR_SIZE, sizeof(char));
    pairs[i].value = calloc(PAIR_SIZE, sizeof(char));

    if (pairs[i].key == NULL || pairs[i].value == NULL) {
      fprintf(stderr, "failed to allocate memory: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  return pairs;
}

static void free_pair_array(Pair *pairs, int size) {
  for (int i = 0; i < size; i++) {
    free(pairs[i].key);
    free(pairs[i].value);
  }
  free(pairs);
}

void parse_config(Config *config) {
  Pair *pairs;
  FILE *file;
  char line[PAIR_SIZE];
  int counter = 0;

  config->name = NULL;
  config->url = NULL;
  config->interval = 0;
  config->platform = UNKNOWN;

  pairs = init_pair_array(PAIR_AMOUNT);

  file = fopen(CONFIG_PATH, "r");
  if (file == NULL) {
    fprintf(stderr, "%s couldn't be opened for reading with %s\n", CONFIG_PATH,
            strerror(errno));
    free_pair_array(pairs, PAIR_AMOUNT);
    exit(EXIT_FAILURE);
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    char *key;
    char *separator;
    char *value;

    line[strcspn(line, "\n")] = '\0';

    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    if (counter >= PAIR_AMOUNT) {
      fprintf(stderr, "config in %s has too many lines\n", CONFIG_PATH);
      fclose(file);
      free_pair_array(pairs, PAIR_AMOUNT);
      exit(EXIT_FAILURE);
    }

    separator = strchr(line, '=');
    if (separator == NULL) {
      continue;
    }
    *separator = '\0';
    key = line;
    value = separator + 1;

    snprintf(pairs[counter].key, PAIR_SIZE, "%s", key);
    snprintf(pairs[counter].value, PAIR_SIZE, "%s", value);
    counter++;
  }

  fclose(file);
  file = NULL;

  for (int i = 0; i < counter; i++) {
    if (strcmp(pairs[i].key, "name") == 0) {
      set_string(&config->name, pairs[i].value);
    } else if (strcmp(pairs[i].key, "url") == 0) {
      set_string(&config->url, pairs[i].value);
    } else if (strcmp(pairs[i].key, "interval") == 0) {
      char *end = NULL;
      unsigned long interval;

      errno = 0;
      interval = strtoul(pairs[i].value, &end, 10);
      if (errno == 0 && end != pairs[i].value && *end == '\0' && interval > 0 &&
          interval <= UINT_MAX) {
        config->interval = (unsigned int)interval;
      }
    } else if (strcmp(pairs[i].key, "platform") == 0) {
      char *end = NULL;
      unsigned long platform;

      errno = 0;
      platform = strtoul(pairs[i].value, &end, 10);
      if (errno == 0 && end != pairs[i].value && *end == '\0' &&
          platform <= UNKNOWN) {
        config->platform = (OS)platform;
      }
    }
  }

  free_pair_array(pairs, PAIR_AMOUNT);
  pairs = NULL;

  if (config->platform == UNKNOWN) {
    load_platform(config);
  }
}

void write_config(Config *config) {
  FILE *file = fopen(CONFIG_PATH, "w");
  if (file == NULL) {
    fprintf(stderr, "%s couldn't be opened for writing with %s\n", CONFIG_PATH,
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  fprintf(file, "name=%s\n", config->name);
  fprintf(file, "url=%s\n", config->url);
  fprintf(file, "interval=%u\n", config->interval);
  fprintf(file, "platform=%u\n", config->platform);

  fclose(file);
  file = NULL;
}

void load_config(Config *config) {
  FILE *file = fopen(CONFIG_PATH, "r");

  config->name = NULL;
  config->url = NULL;
  config->platform = UNKNOWN;
  config->interval = 0;

  if (file == NULL) {
    set_string(&config->name, NAME);
    set_string(&config->url, "");
    config->interval = INTERVAL_SECONDS;
    config->platform = UNKNOWN;

    write_config(config);

    return;
  }

  fclose(file);
  file = NULL;

  parse_config(config);

  if (config->name == NULL) {
    set_string(&config->name, NAME);
  }
  if (config->url == NULL) {
    set_string(&config->url, "");
  }
}

void load_platform(Config *config) {
  FILE *file = fopen("/etc/os-release", "r");
  if (file == NULL) {
    fprintf(stderr, "failed to open /etc/os-release: %s\n", strerror(errno));
    config->platform = UNKNOWN;
    return;
  }
  char line[PAIR_SIZE];
  config->platform = UNKNOWN;

  while (fgets(line, sizeof(line), file) != NULL) {
    char *value;

    if (strncmp(line, "ID=", 3) != 0) {
      continue;
    }

    value = line + 3;
    value[strcspn(value, "\r\n")] = '\0';

    if (value[0] == '"' || value[0] == '\'') {
      size_t length = strlen(value);

      if (length >= 2 && value[length - 1] == value[0]) {
        value[length - 1] = '\0';
      }
      value++;
    }

    if (strcmp(value, "ubuntu") == 0) {
      config->platform = UBUNTU;
    } else if (strcmp(value, "debian") == 0) {
      config->platform = DEBIAN;
    } else if (strcmp(value, "fedora") == 0) {
      config->platform = FEDORA;
    } else if (strcmp(value, "arch") == 0) {
      config->platform = ARCH;
    } else if (strcmp(value, "endeavouros") == 0) {
      config->platform = ARCH;
    }
  }

  fclose(file);
  file = NULL;
}

void cleanup_config(Config *config) {
  free(config->name);
  free(config->url);
  config->name = NULL;
  config->url = NULL;
  config->interval = 0;
}
