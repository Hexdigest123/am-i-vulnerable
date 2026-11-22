#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "rss.h"
#include "system.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    /* nanosleep() reports the time left, so just try again. */
  }
}

int main(int argc, char **argv) {
  struct sigaction action = {
      .sa_handler = handle_signal,
  };
  unsigned interval;

  if (argc > 1 && strcmp(argv[1], "--help") == 0) {
    printf("Usage: am-i-vulnerable [--help]\n");
    printf("\n");
    printf("Configuration is read from %s using 'key=value' lines.\n",
           CONFIG_PATH);
    printf("Expected keys:\n");
    printf("  name      instance name (default: %s)\n", NAME);
    printf("  url       URL to check, must not be empty\n");
    printf(
        "  interval  seconds between checks, positive integer (default: %u)\n",
        INTERVAL_SECONDS);
    printf("  platform  OS platform (ubuntu, debian, fedora)\n");
    printf("\n");
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

  // initialization

  Config config;
  load_config(&config);

  if (config.interval == 0) {
    fprintf(stdout,
            "interval not set or invalid format, using default: %u seconds\n",
            INTERVAL_SECONDS);
    config.interval = INTERVAL_SECONDS;
  }
  interval = config.interval;

  if (strcmp(config.url, "") == 0) {
    fprintf(stderr, "%s: url initialized with '%s' is not in readable format\n",
            CONFIG_PATH, config.url);
    return EXIT_FAILURE;
  }

  if (config.platform == UNKNOWN) {
    fprintf(stderr, "platform not available or invalid format\n");
    return EXIT_FAILURE;
  }

  if (init_rss() != 0) {
    return EXIT_FAILURE;
  }

  Package *system_packages =
      (Package *)malloc(SYSTEM_MAX_PACKAGES * sizeof(Package));
  if (system_packages == NULL) {
    fprintf(stderr, "failed to allocate memory for packages\n");
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < SYSTEM_MAX_PACKAGES; i++) {
    system_packages[i].name = (char *)malloc(sizeof(char) * 128);
    system_packages[i].version = (char *)malloc(sizeof(char) * 128);
    if (system_packages[i].name == NULL || system_packages[i].version == NULL) {
      fprintf(stderr, "failed to allocate memory for package\n");
      return EXIT_FAILURE;
    }
  }

  load_packages(&config, system_packages);

  // end of initialization

  if (sigemptyset(&action.sa_mask) == -1 ||
      sigaction(SIGINT, &action, NULL) == -1 ||
      sigaction(SIGTERM, &action, NULL) == -1) {
    fprintf(stderr, "sigaction failed: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  fprintf(stderr, "am-i-vulnerable started (interval: %u seconds)\n", interval);

  while (keep_running) {
    RssFeed *feed = read_rss(config.url);

    if (feed != NULL) {
      char handled[SYSTEM_MAX_PACKAGES] = {0};

      for (size_t i = 0; i < feed->item_count; i++) {
        RssItem *item = &feed->items[i];

        for (size_t j = 0; j < item->package_count; j++) {
          /*
          Updates whenever the version is not equal to the fixed version.
          // TODO: handle version comparison by implementing a version
          comparison function
          */
          RssPackage *package = &item->packages[j];

          if (package->name == NULL || package->fixed == NULL) {
            continue;
          }

          for (size_t k = 0; k < SYSTEM_MAX_PACKAGES; k++) {
            if (system_packages[k].name == NULL) {
              break;
            }

            if (handled[k]) {
              continue;
            }

            if (strcmp(system_packages[k].name, package->name) != 0) {
              continue;
            }

            if (strcmp(system_packages[k].version, package->fixed) != 0) {
              handled[k] = 1;
              update_package(&config, &system_packages[k]);
            }
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

  cleanup_rss();
  cleanup_packages(system_packages);
  cleanup_config(&config);
  fprintf(stderr, "am-i-vulnerable stopped\n");

  return EXIT_SUCCESS;
}
