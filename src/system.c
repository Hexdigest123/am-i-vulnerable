#define _POSIX_C_SOURCE 200809L

#include "system.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const APT_LIST_ARGS[] = {"apt", "list", "--installed", NULL};
static const char *const DNF_LIST_ARGS[] = {"dnf", "-q", "list", "installed",
                                            NULL};
static const char *const PACMAN_LIST_ARGS[] = {"pacman", "-Q", NULL};

static int is_valid_package_name(const char *name) {
  const char *p;

  if (name == NULL || !isalnum((unsigned char)name[0])) {
    return 0;
  }
  for (p = name + 1; *p != '\0'; p++) {
    unsigned char c = (unsigned char)*p;
    if (!isalnum(c) && c != '+' && c != '-' && c != '.' && c != '_') {
      return 0;
    }
  }
  return 1;
}

static pid_t run_capture(const char *const argv[], FILE **out) {
  int fds[2];
  pid_t pid;

  if (pipe(fds) == -1) {
    return -1;
  }

  pid = fork();
  if (pid == -1) {
    close(fds[0]);
    close(fds[1]);
    return -1;
  }

  if (pid == 0) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) == -1) {
      _exit(127);
    }
    close(fds[1]);
    execvp(argv[0], (char *const *)argv);
    _exit(127);
  }

  close(fds[1]);
  *out = fdopen(fds[0], "r");
  if (*out == NULL) {
    close(fds[0]);
    waitpid(pid, NULL, 0);
    return -1;
  }
  return pid;
}

static int run_command(const char *const argv[]) {
  pid_t pid;
  int status;

  pid = fork();
  if (pid == -1) {
    return -1;
  }

  if (pid == 0) {
    execvp(argv[0], (char *const *)argv);
    fprintf(stderr, "failed to execute '%s': %s\n", argv[0], strerror(errno));
    _exit(127);
  }

  if (waitpid(pid, &status, 0) == -1) {
    return -1;
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return 0;
  }
  return -1;
}

int load_packages(Config *config, Package *packages) {
  const char *const *argv;
  FILE *pipe;
  pid_t pid;
  char line[PAIR_SIZE];
  size_t count = 0;
  int status;

  switch (config->platform) {
  case UBUNTU:
  case DEBIAN:
    argv = APT_LIST_ARGS;
    break;
  case FEDORA:
    argv = DNF_LIST_ARGS;
    break;
  case ARCH:
    argv = PACMAN_LIST_ARGS;
    break;
  default:
    fprintf(stderr, "cannot list packages, platform is unknown\n");
    return -1;
  }

  pid = run_capture(argv, &pipe);
  if (pid == -1) {
    fprintf(stderr, "failed to run '%s': %s\n", argv[0], strerror(errno));
    return -1;
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

    separator = strchr(name, '/');
    if (separator != NULL) {
      *separator = '\0';
    }

    packages[count].name = strdup(name);
    packages[count].version = strdup(version);
    if (packages[count].name == NULL || packages[count].version == NULL) {
      fprintf(stderr, "failed to allocate memory for package\n");
      free(packages[count].name);
      free(packages[count].version);
      packages[count].name = NULL;
      packages[count].version = NULL;
      fclose(pipe);
      waitpid(pid, &status, 0);
      return -1;
    }
    count++;
  }

  if (fclose(pipe) != 0) {
    fprintf(stderr, "failed to read output of '%s': %s\n", argv[0],
            strerror(errno));
  }

  if (waitpid(pid, &status, 0) == -1) {
    fprintf(stderr, "failed to wait for '%s': %s\n", argv[0], strerror(errno));
    return -1;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "'%s' did not exit successfully\n", argv[0]);
    return -1;
  }

  packages[count].name = NULL;
  packages[count].version = NULL;
  return 0;
}

int update_package(Config *config, Package *package) {
  const char *argv[8];
  size_t argc = 0;

  if (!is_valid_package_name(package->name)) {
    fprintf(stderr, "refusing to update package with unsafe name '%s'\n",
            package->name != NULL ? package->name : "(null)");
    return -1;
  }

  switch (config->platform) {
  case UBUNTU:
  case DEBIAN:
    argv[argc++] = "apt";
    argv[argc++] = "install";
    argv[argc++] = "--only-upgrade";
    argv[argc++] = "-y";
    break;
  case FEDORA:
    argv[argc++] = "dnf";
    argv[argc++] = "upgrade";
    argv[argc++] = "-y";
    break;
  case ARCH:
    argv[argc++] = "pacman";
    argv[argc++] = "-S";
    argv[argc++] = "--noconfirm";
    break;
  default:
    fprintf(stderr, "cannot update package, platform is unknown\n");
    return -1;
  }

  argv[argc++] = package->name;
  argv[argc] = NULL;

  return run_command(argv);
}

void cleanup_packages(Package *packages) {
  for (size_t i = 0; i < SYSTEM_MAX_PACKAGES; i++) {
    free(packages[i].name);
    free(packages[i].version);
  }
  free(packages);
}
