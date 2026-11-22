#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "rss.h"
#include "system.h"
#include "version.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signal_number) {
  (void)signal_number;
  keep_running = 0;
}

static void sleep_seconds(unsigned seconds) {
  struct timespec remaining = {
      .tv_sec = seconds,
      .tv_nsec = 0,
  };

  while (keep_running && nanosleep(&remaining, &remaining) == -1 &&
         errno == EINTR) {
  }
}

typedef struct HandledSet {
  char **items;
  size_t count;
  size_t capacity;
} HandledSet;

static int handled_contains(const HandledSet *set, const char *key) {
  for (size_t i = 0; i < set->count; i++) {
    if (strcmp(set->items[i], key) == 0) {
      return 1;
    }
  }
  return 0;
}

static int handled_add(HandledSet *set, const char *key) {
  if (set->count == set->capacity) {
    size_t capacity = set->capacity == 0 ? 16 : set->capacity * 2;
    char **items = realloc(set->items, capacity * sizeof(*items));
    if (items == NULL) {
      return -1;
    }
    set->items = items;
    set->capacity = capacity;
  }
  set->items[set->count] = strdup(key);
  if (set->items[set->count] == NULL) {
    return -1;
  }
  set->count++;
  return 0;
}

static void handled_free(HandledSet *set) {
  for (size_t i = 0; i < set->count; i++) {
    free(set->items[i]);
  }
  free(set->items);
  set->items = NULL;
  set->count = 0;
  set->capacity = 0;
}

static char *make_handled_key(const char *name, const char *fixed) {
  size_t length = strlen(name) + strlen(fixed) + 2;
  char *key = malloc(length);

  if (key == NULL) {
    return NULL;
  }
  snprintf(key, length, "%s=%s", name, fixed);
  return key;
}

static int ecosystem_matches(OS platform, const char *ecosystem) {
  const char *prefix;
  size_t length;

  if (ecosystem == NULL || ecosystem[0] == '\0') {
    return 1;
  }

  switch (platform) {
  case UBUNTU:
    prefix = "ubuntu";
    break;
  case DEBIAN:
    prefix = "debian";
    break;
  case FEDORA:
    prefix = "fedora";
    break;
  case ARCH:
    prefix = "arch";
    break;
  default:
    return 0;
  }

  length = strlen(prefix);
  if (strncasecmp(ecosystem, prefix, length) != 0) {
    return 0;
  }
  return ecosystem[length] == '\0' || ecosystem[length] == ':';
}

static int is_valid_url(const char *url) {
  const char *p;

  if (url == NULL || url[0] == '\0') {
    return 0;
  }
  for (p = url; *p != '\0'; p++) {
    unsigned char c = (unsigned char)*p;
    if (c <= 0x20 || c == 0x7f) {
      return 0;
    }
  }
#ifndef DEV
  if (strncasecmp(url, "https://", 8) != 0) {
    return 0;
  }
#endif
  return 1;
}

static unsigned parse_interval_env(const char *value, int *valid) {
  char *end = NULL;
  unsigned long interval;

  errno = 0;
  interval = strtoul(value, &end, 10);
  if (errno == 0 && end != value && *end == '\0' && interval > 0 &&
      interval <= UINT_MAX) {
    *valid = 1;
    return (unsigned)interval;
  }
  *valid = 0;
  return 0;
}

int main(int argc, char **argv) {
  struct sigaction action = {
      .sa_handler = handle_signal,
  };
  unsigned interval;
  Config config;
  Package *system_packages;
  HandledSet handled = {0};

  if (argc > 1 && strcmp(argv[1], "--help") == 0) {
    printf("Usage: am-i-vulnerable [--help]\n");
    printf("\n");
    printf("Configuration is read from %s using 'key=value' lines.\n",
           CONFIG_PATH);
    printf("Expected keys:\n");
    printf("  name      instance name (default: %s)\n", NAME);
    printf("  url       HTTPS URL to check, must not be empty\n");
    printf(
        "  interval  seconds between checks, positive integer (default: %u)\n",
        INTERVAL_SECONDS);
    printf("  platform  OS platform (ubuntu, debian, fedora)\n");
    printf("\n");
    printf("The interval can also be set with AMI_VULNERABLE_INTERVAL_SECONDS.\n");
    printf("Empty lines and lines starting with '#' are ignored.\n");
    return EXIT_SUCCESS;
  }

  if (argc > 1) {
    fprintf(stderr, "Unknown option: %s\n", argv[1]);
    fprintf(stderr, "Usage: am-i-vulnerable [--help]\n");
    return EXIT_FAILURE;
  }

#ifndef DEV
  if (geteuid() != 0) {
    fprintf(stderr, "am-i-vulnerable requires effective root privileges\n");
    return EXIT_FAILURE;
  }
#endif

  load_config(&config);

  {
    const char *env_interval = getenv("AMI_VULNERABLE_INTERVAL_SECONDS");
    if (env_interval != NULL) {
      int valid;
      unsigned parsed = parse_interval_env(env_interval, &valid);
      if (valid) {
        config.interval = parsed;
      } else {
        fprintf(stderr,
                "ignoring invalid AMI_VULNERABLE_INTERVAL_SECONDS='%s'\n",
                env_interval);
      }
    }
  }

  if (config.interval == 0) {
    fprintf(stdout,
            "interval not set or invalid format, using default: %u seconds\n",
            INTERVAL_SECONDS);
    config.interval = INTERVAL_SECONDS;
  }
  interval = config.interval;

  if (!is_valid_url(config.url)) {
#ifndef DEV
    fprintf(stderr,
            "%s: url '%s' is invalid: release builds require a non-empty "
            "https:// URL without control characters\n",
            CONFIG_PATH, config.url);
#else
    fprintf(stderr, "%s: url '%s' is empty or contains control characters\n",
            CONFIG_PATH, config.url);
#endif
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  if (config.platform == UNKNOWN) {
    fprintf(stderr, "platform not available or invalid format\n");
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  if (init_rss() != 0) {
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  system_packages = calloc(SYSTEM_MAX_PACKAGES, sizeof(*system_packages));
  if (system_packages == NULL) {
    fprintf(stderr, "failed to allocate memory for packages\n");
    cleanup_rss();
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  if (load_packages(&config, system_packages) != 0) {
    fprintf(stderr, "failed to list installed packages\n");
    cleanup_packages(system_packages);
    cleanup_rss();
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  if (sigemptyset(&action.sa_mask) == -1 ||
      sigaction(SIGINT, &action, NULL) == -1 ||
      sigaction(SIGTERM, &action, NULL) == -1) {
    fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
    cleanup_packages(system_packages);
    cleanup_rss();
    cleanup_config(&config);
    return EXIT_FAILURE;
  }

  fprintf(stderr, "am-i-vulnerable started (interval: %u seconds)\n", interval);

  while (keep_running) {
    RssFeed *feed = read_rss(config.url);

    if (feed != NULL) {
      for (size_t i = 0; i < feed->item_count && keep_running; i++) {
        RssItem *item = &feed->items[i];

        for (size_t j = 0; j < item->package_count; j++) {
          RssPackage *package = &item->packages[j];

          if (package->name == NULL || package->fixed == NULL) {
            continue;
          }

          if (!ecosystem_matches(config.platform, package->ecosystem)) {
            continue;
          }

          for (size_t k = 0; k < SYSTEM_MAX_PACKAGES; k++) {
            char *key;

            if (system_packages[k].name == NULL) {
              break;
            }

            if (strcmp(system_packages[k].name, package->name) != 0) {
              continue;
            }

            if (version_compare(system_packages[k].version, package->fixed) >=
                0) {
              continue;
            }

            key = make_handled_key(package->name, package->fixed);
            if (key == NULL) {
              fprintf(stderr, "out of memory, skipping update of %s\n",
                      package->name);
              continue;
            }

            if (handled_contains(&handled, key)) {
              free(key);
              continue;
            }

            fprintf(stderr,
                    "am-i-vulnerable: %s %s is older than fixed version %s, "
                    "updating\n",
                    system_packages[k].name, system_packages[k].version,
                    package->fixed);

            if (update_package(&config, &system_packages[k]) == 0) {
              if (handled_add(&handled, key) != 0) {
                fprintf(stderr, "warning: could not track handled package\n");
              }
            } else {
              fprintf(stderr,
                      "am-i-vulnerable: update of %s failed, will retry on "
                      "next interval\n",
                      system_packages[k].name);
            }

            free(key);
          }
        }
      }

      free_rss(feed);
    } else {
      fprintf(stderr, "failed to read RSS feed\n");
    }

    fprintf(stdout, "am-i-vulnerable sleeping for %u seconds\n", interval);

    sleep_seconds(interval);
  }

  handled_free(&handled);
  cleanup_rss();
  cleanup_packages(system_packages);
  cleanup_config(&config);
  fprintf(stderr, "am-i-vulnerable stopped\n");

  return EXIT_SUCCESS;
}
