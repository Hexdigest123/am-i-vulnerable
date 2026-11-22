#ifndef RSS_H
#define RSS_H

#include <stddef.h>

#define RSS_MAX_PACKAGES 20

typedef struct RssAtomLink {
  char *href;
  char *rel;
  char *type;
} RssAtomLink;

typedef struct RssChannel {
  char *title;
  char *link;
  char *description;
  char *language;
  unsigned int ttl;
  char *last_build_date;
  RssAtomLink atom_link;
} RssChannel;

typedef struct RssGuid {
  char *value;
  int is_permalink;
} RssGuid;

typedef struct RssPackage {
  char *ecosystem;
  char *name;
  char *purl;
  char *introduced;
  char *fixed;
  char *last_affected;
  char *binaries;
  char *source;
  char *source_url;
} RssPackage;

typedef struct RssItem {
  char *title;
  char *link;
  RssGuid guid;
  char *pub_date;
  char *description;
  char *content_encoded;
  char **categories;
  size_t category_count;
  RssPackage *packages;
  size_t package_count;
} RssItem;

typedef struct RssFeed {
  char *version;
  RssChannel channel;
  RssItem *items;
  size_t item_count;
} RssFeed;

int init_rss(void);
void cleanup_rss(void);

RssFeed *read_rss(const char *url);

RssFeed *parse_rss(const char *xml, size_t length);

void free_rss(RssFeed *feed);

#endif
