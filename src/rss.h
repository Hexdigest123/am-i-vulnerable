#ifndef RSS_H
#define RSS_H

#include <stddef.h>

/*
 * Model of the LogiQ CVE RSS feed:
 *
 *   <rss version="2.0">
 *     <channel>
 *       <title>...</title>
 *       <link>...</link>
 *       <description>...</description>
 *       <language>en</language>
 *       <ttl>60</ttl>
 *       <atom:link href="..." rel="self" type="application/rss+xml"/>
 *       <lastBuildDate>...</lastBuildDate>
 *       <item>
 *         <title>[CRITICAL 9.8] CVE-... - ...</title>
 *         <link>...</link>
 *         <guid isPermaLink="true">...</guid>
 *         <pubDate>...</pubDate>
 *         <description>...</description>
 *         <content:encoded><![CDATA[...]]></content:encoded>
 *         <category>CRITICAL</category>
 *         ...
 *         <logiq:package ecosystem="Ubuntu:24.04:LTS" name="apache2"
 *                        purl="pkg:deb/ubuntu/apache2?..."
 *                        introduced="0" fixed="2.4.58-1ubuntu8.19"
 *                        binaries="apache2,apache2-bin"
 *                        source="osv" sourceUrl="https://..." />
 *         ...
 *       </item>
 *       ...
 *     </channel>
 *   </rss>
 *
 * <logiq:package> has no text content; all data lives in its attributes.
 */

/* The feed contract allows at most 20 <logiq:package> elements per item. */
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

/*
 * One <logiq:package> element. Empty or omitted attributes stay NULL.
 * "introduced" and "fixed" are kept as strings because they are versions,
 * not numbers; introduced="0" is a literal value, not "missing".
 */
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

/* Call once before read_rss()/parse_rss(). */
int init_rss(void);
void cleanup_rss(void);

/* Fetches a feed over HTTP(S) and parses it. Returns NULL on failure. */
RssFeed *read_rss(const char *url);

/* Parses an in-memory XML document. Returns NULL on failure. */
RssFeed *parse_rss(const char *xml, size_t length);

void free_rss(RssFeed *feed);

#endif
