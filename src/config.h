#ifndef CONFIG_H
#define CONFIG_H

#define PAIR_AMOUNT 64
#define PAIR_SIZE 1024
#define INTERVAL_SECONDS 18000U /* 5 hours */
#define NAME "am-i-vulnerable"

#ifndef CONFIG_PATH
#ifdef DEV
#define CONFIG_PATH "am-i-vulnerable.conf"
#else
#define CONFIG_PATH "/etc/am-i-vulnerable.conf"
#endif
#endif

typedef enum OS { UBUNTU, DEBIAN, FEDORA, ARCH, UNKNOWN } OS;

extern const char *PACKAGE_MANAGER[];

typedef struct Pair {
  char *key;
  char *value;
} Pair;

typedef struct Config {
  char *name;
  char *url;
  OS platform;
  unsigned int interval;
} Config;

void parse_config(Config *config);
void load_platform(Config *config);
void load_config(Config *config);
void write_config(Config *config);
void cleanup_config(Config *config);
#endif
