#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef VERSION
#define VERSION "dev"
#endif

#define DEFAULT_INTERVAL_SECONDS 18000U /* 5 hours */

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    keep_running = 0;
}

static unsigned parse_interval(void)
{
    const char *value = getenv("AMI_VULNERABLE_INTERVAL_SECONDS");
    char *end = NULL;
    unsigned long interval;

    if (value == NULL || *value == '\0') {
        return DEFAULT_INTERVAL_SECONDS;
    }

    errno = 0;
    interval = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        interval < 1 || interval > UINT_MAX) {
        fprintf(stderr,
                "Invalid AMI_VULNERABLE_INTERVAL_SECONDS=%s; using %u seconds\n",
                value, DEFAULT_INTERVAL_SECONDS);
        return DEFAULT_INTERVAL_SECONDS;
    }

    return (unsigned)interval;
}

static void sleep_seconds(unsigned seconds)
{
    struct timespec remaining = {
        .tv_sec = seconds,
        .tv_nsec = 0,
    };

    while (keep_running && nanosleep(&remaining, &remaining) == -1 &&
           errno == EINTR) {
        /* nanosleep() reports the time left, so just try again. */
    }
}

static void check_for_vulnerabilities(void)
{
    /*
     * TODO: Read the vulnerability feed, compare it with installed packages,
     * and update or notify the administrator.
     *
     * Keep this function small and put the real logic in separate .c files
     * when you start adding functionality.
     */
    fprintf(stderr, "Checking for vulnerabilities...\n");
}

int main(int argc, char **argv)
{
    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    unsigned interval;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("am-i-vulnerable %s\n", VERSION);
        return EXIT_SUCCESS;
    }

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: am-i-vulnerable [--help] [--version]\n");
        return EXIT_SUCCESS;
    }

    if (argc > 1) {
        fprintf(stderr, "Unknown option: %s\n", argv[1]);
        fprintf(stderr, "Usage: am-i-vulnerable [--help] [--version]\n");
        return EXIT_FAILURE;
    }

    interval = parse_interval();

    if (sigemptyset(&action.sa_mask) == -1 ||
        sigaction(SIGINT, &action, NULL) == -1 ||
        sigaction(SIGTERM, &action, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "am-i-vulnerable %s started (interval: %u seconds)\n",
            VERSION, interval);

    while (keep_running) {
        check_for_vulnerabilities();
        sleep_seconds(interval);
    }

    fprintf(stderr, "am-i-vulnerable stopped\n");
    return EXIT_SUCCESS;
}
