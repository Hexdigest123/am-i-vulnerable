#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static FILE *open_config_read(const char *path) {
  int fd;
  struct stat st;
  FILE *file;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd == -1) {
    return NULL;
  }
  if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
    close(fd);
    errno = EINVAL;
    return NULL;
  }
  file = fdopen(fd, "r");
  if (file == NULL) {
    close(fd);
    return NULL;
  }
  return file;
}

void parse_config(Config *config, FILE *file) {
  Pair *pairs;
  char line[PAIR_SIZE];
  int counter = 0;

  config->name = NULL;
  config->url = NULL;
  config->interval = 0;
  config->platform = UNKNOWN;

  pairs = init_pair_array(PAIR_AMOUNT);

  while (fgets(line, sizeof(line), file) != NULL) {
    char *key;
    char *separator;
    char *value;

    line[strcspn(line, "\r\n")] = '\0';

    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    if (counter >= PAIR_AMOUNT) {
      fprintf(stderr, "config in %s has too many lines\n", CONFIG_PATH);
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

  if (config->platform == UNKNOWN) {
    load_platform(config);
  }
}

int write_config(Config *config) {
  int fd;
  FILE *file;

  fd = open(CONFIG_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0640);
  if (fd == -1) {
    fprintf(stderr, "%s couldn't be opened for writing: %s\n", CONFIG_PATH,
            strerror(errno));
    return -1;
  }
  if (fchmod(fd, 0640) == -1) {
    fprintf(stderr, "%s: fchmod failed: %s\n", CONFIG_PATH, strerror(errno));
  }

  file = fdopen(fd, "w");
  if (file == NULL) {
    fprintf(stderr, "%s couldn't be opened for writing: %s\n", CONFIG_PATH,
            strerror(errno));
    close(fd);
    return -1;
  }

  fprintf(file, "name=%s\n", config->name);
  fprintf(file, "url=%s\n", config->url);
  fprintf(file, "interval=%u\n", config->interval);
  fprintf(file, "platform=%u\n", config->platform);

  if (fclose(file) != 0) {
    fprintf(stderr, "%s couldn't be written: %s\n", CONFIG_PATH,
            strerror(errno));
    return -1;
  }
  return 0;
}

void load_config(Config *config) {
  FILE *file;

  config->name = NULL;
  config->url = NULL;
  config->platform = UNKNOWN;
  config->interval = 0;

  file = open_config_read(CONFIG_PATH);
  if (file == NULL) {
    if (errno == ENOENT) {
      set_string(&config->name, NAME);
      set_string(&config->url, "");
      config->interval = INTERVAL_SECONDS;
      load_platform(config);
      if (write_config(config) != 0) {
        fprintf(stderr,
                "warning: could not write default config to %s; continuing "
                "with defaults\n",
                CONFIG_PATH);
      }
      return;
    }
    fprintf(stderr, "%s couldn't be opened for reading: %s\n", CONFIG_PATH,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  parse_config(config, file);
  fclose(file);

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
}

void cleanup_config(Config *config) {
  free(config->name);
  free(config->url);
  config->name = NULL;
  config->url = NULL;
  config->interval = 0;
}
