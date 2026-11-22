#define _POSIX_C_SOURCE 200809L

#include "rss.h"

#include <curl/curl.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RSS_MAX_BYTES (4U * 1024U * 1024U)

#define ATOM_NS "http://www.w3.org/2005/Atom"
#define CONTENT_NS "http://purl.org/rss/1.0/modules/content/"
#define LOGIQ_NS "https://logiqit.de/ns/cve/1"

#ifndef VERSION
#define VERSION "dev"
#endif

struct RssResponse {
  char *data;
  size_t length;
};

static size_t write_callback(char *contents, size_t size, size_t nmemb,
                             void *userdata) {
  struct RssResponse *response = userdata;
  size_t bytes;
  size_t needed;
  char *data;

  if (size != 0 && nmemb > SIZE_MAX / size) {
    return 0;
  }
  bytes = size * nmemb;

  if (bytes == 0 || response->length > RSS_MAX_BYTES ||
      bytes > RSS_MAX_BYTES - response->length) {
    return 0;
  }

  needed = response->length + bytes + 1;
  data = realloc(response->data, needed);
  if (data == NULL) {
    return 0;
  }

  response->data = data;
  memcpy(response->data + response->length, contents, bytes);
  response->length += bytes;
  response->data[response->length] = '\0';
  return bytes;
}

static int fetch(const char *url, struct RssResponse *response) {
  CURL *curl = curl_easy_init();
  CURLcode result;
  long status = 0;

  if (curl == NULL) {
    fprintf(stderr, "rss: failed to initialize curl\n");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "am-i-vulnerable/" VERSION);
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)RSS_MAX_BYTES);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

  result = curl_easy_perform(curl);
  if (result == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  }
  curl_easy_cleanup(curl);

  if (result != CURLE_OK) {
    fprintf(stderr, "rss: fetch of %s failed: %s\n", url,
            curl_easy_strerror(result));
    return -1;
  }
  if (status < 200 || status >= 300) {
    fprintf(stderr, "rss: fetch of %s returned HTTP %ld\n", url, status);
    return -1;
  }

  return 0;
}

static int is_element(const xmlNode *node, const char *name) {
  return node->type == XML_ELEMENT_NODE &&
         xmlStrcasecmp(node->name, BAD_CAST name) == 0;
}

/* RSS elements such as <title> and <link> are not namespaced. */
static int is_rss_element(const xmlNode *node, const char *name) {
  return is_element(node, name) && (node->ns == NULL || node->ns->href == NULL);
}

static int is_namespaced_element(const xmlNode *node, const char *namespace_uri,
                                 const char *name) {
  return node->type == XML_ELEMENT_NODE && node->ns != NULL &&
         node->ns->href != NULL &&
         strcmp((const char *)node->ns->href, namespace_uri) == 0 &&
         strcmp((const char *)node->name, name) == 0;
}

static int set_node_text(const xmlNode *node, char **target) {
  xmlChar *text = xmlNodeGetContent(node);
  char *copy;

  if (text == NULL) {
    return 0;
  }

  copy = strdup((const char *)text);
  xmlFree(text);
  if (copy == NULL) {
    return -1;
  }

  free(*target);
  *target = copy;
  return 0;
}

static int set_node_prop(const xmlNode *node, const char *name, char **target) {
  xmlChar *value = xmlGetProp((xmlNode *)node, BAD_CAST name);
  char *copy;

  if (value == NULL) {
    return 0;
  }

  copy = strdup((const char *)value);
  xmlFree(value);
  if (copy == NULL) {
    return -1;
  }

  free(*target);
  *target = copy;
  return 0;
}

static int add_category(RssItem *item, const xmlNode *node) {
  xmlChar *text = xmlNodeGetContent(node);
  char *copy;
  char **categories;

  if (text == NULL) {
    return 0;
  }

  copy = strdup((const char *)text);
  xmlFree(text);
  if (copy == NULL) {
    return -1;
  }

  categories = realloc(item->categories,
                       (item->category_count + 1) * sizeof(*categories));
  if (categories == NULL) {
    free(copy);
    return -1;
  }

  item->categories = categories;
  item->categories[item->category_count++] = copy;
  return 0;
}

static int parse_package(const xmlNode *node, RssPackage *package) {
  /*
   * <logiq:package> has no text content. Every value is an attribute and
   * omitted attributes stay NULL. Attribute order does not matter here.
   */
  if (set_node_prop(node, "ecosystem", &package->ecosystem) != 0 ||
      set_node_prop(node, "name", &package->name) != 0 ||
      set_node_prop(node, "purl", &package->purl) != 0 ||
      set_node_prop(node, "introduced", &package->introduced) != 0 ||
      set_node_prop(node, "fixed", &package->fixed) != 0 ||
      set_node_prop(node, "lastAffected", &package->last_affected) != 0 ||
      set_node_prop(node, "binaries", &package->binaries) != 0 ||
      set_node_prop(node, "source", &package->source) != 0 ||
      set_node_prop(node, "sourceUrl", &package->source_url) != 0) {
    return -1;
  }

  return 0;
}

static int add_package(RssItem *item, const xmlNode *node) {
  RssPackage *packages;

  if (item->package_count >= RSS_MAX_PACKAGES) {
    return 0;
  }

  packages =
      realloc(item->packages, (item->package_count + 1) * sizeof(*packages));
  if (packages == NULL) {
    return -1;
  }
  item->packages = packages;

  memset(&item->packages[item->package_count], 0,
         sizeof(item->packages[item->package_count]));
  item->package_count++;

  /*
   * Increment the count first so free_rss() also releases partially filled
   * fields if an allocation below fails.
   */
  return parse_package(node, &item->packages[item->package_count - 1]);
}

static void set_ttl(const xmlNode *node, unsigned int *ttl) {
  xmlChar *text = xmlNodeGetContent(node);
  char *end = NULL;
  unsigned long value;

  if (text == NULL) {
    return;
  }

  errno = 0;
  value = strtoul((const char *)text, &end, 10);
  if (errno == 0 && end != (char *)text && *end == '\0' && value <= UINT_MAX) {
    *ttl = (unsigned int)value;
  }
  xmlFree(text);
}

static int parse_channel(const xmlNode *node, RssChannel *channel) {
  for (const xmlNode *child = node->children; child != NULL;
       child = child->next) {
    if (is_rss_element(child, "title")) {
      if (set_node_text(child, &channel->title) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "link")) {
      if (set_node_text(child, &channel->link) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "description")) {
      if (set_node_text(child, &channel->description) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "language")) {
      if (set_node_text(child, &channel->language) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "ttl")) {
      set_ttl(child, &channel->ttl);
    } else if (is_rss_element(child, "lastBuildDate")) {
      if (set_node_text(child, &channel->last_build_date) != 0) {
        return -1;
      }
    } else if (is_namespaced_element(child, ATOM_NS, "link")) {
      if (set_node_prop(child, "href", &channel->atom_link.href) != 0 ||
          set_node_prop(child, "rel", &channel->atom_link.rel) != 0 ||
          set_node_prop(child, "type", &channel->atom_link.type) != 0) {
        return -1;
      }
    }
  }

  return 0;
}

static int parse_item(const xmlNode *node, RssItem *item) {
  item->guid.is_permalink = 1;

  for (const xmlNode *child = node->children; child != NULL;
       child = child->next) {
    if (is_rss_element(child, "title")) {
      if (set_node_text(child, &item->title) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "link")) {
      if (set_node_text(child, &item->link) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "guid")) {
      xmlChar *is_permalink;

      if (set_node_text(child, &item->guid.value) != 0) {
        return -1;
      }
      is_permalink = xmlGetProp((xmlNode *)child, BAD_CAST "isPermaLink");
      if (is_permalink != NULL) {
        item->guid.is_permalink =
            xmlStrcasecmp(is_permalink, BAD_CAST "false") != 0;
        xmlFree(is_permalink);
      }
    } else if (is_rss_element(child, "pubDate")) {
      if (set_node_text(child, &item->pub_date) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "description")) {
      if (set_node_text(child, &item->description) != 0) {
        return -1;
      }
    } else if (is_namespaced_element(child, CONTENT_NS, "encoded")) {
      if (set_node_text(child, &item->content_encoded) != 0) {
        return -1;
      }
    } else if (is_rss_element(child, "category")) {
      if (add_category(item, child) != 0) {
        return -1;
      }
    } else if (is_namespaced_element(child, LOGIQ_NS, "package")) {
      if (add_package(item, child) != 0) {
        return -1;
      }
    }
  }

  return 0;
}

static RssFeed *parse_document(xmlDocPtr doc) {
  xmlNode *root = xmlDocGetRootElement(doc);
  xmlNode *channel_node = NULL;
  RssFeed *feed;
  size_t item_count = 0;
  size_t index = 0;

  if (root == NULL || !is_element(root, "rss")) {
    return NULL;
  }

  feed = calloc(1, sizeof(*feed));
  if (feed == NULL) {
    return NULL;
  }

  if (set_node_prop(root, "version", &feed->version) != 0) {
    goto fail;
  }

  for (const xmlNode *child = root->children; child != NULL;
       child = child->next) {
    if (is_rss_element(child, "channel")) {
      channel_node = (xmlNode *)child;
      break;
    }
  }
  if (channel_node == NULL) {
    goto fail;
  }

  if (parse_channel(channel_node, &feed->channel) != 0) {
    goto fail;
  }

  for (const xmlNode *child = channel_node->children; child != NULL;
       child = child->next) {
    if (is_rss_element(child, "item")) {
      item_count++;
    }
  }

  if (item_count > 0) {
    feed->items = calloc(item_count, sizeof(*feed->items));
    if (feed->items == NULL) {
      goto fail;
    }
    feed->item_count = item_count;
  }

  for (const xmlNode *child = channel_node->children; child != NULL;
       child = child->next) {
    if (!is_rss_element(child, "item")) {
      continue;
    }
    if (parse_item(child, &feed->items[index]) != 0) {
      goto fail;
    }
    index++;
  }

  return feed;

fail:
  free_rss(feed);
  return NULL;
}

int init_rss(void) {
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    fprintf(stderr, "rss: curl_global_init() failed\n");
    return -1;
  }

  xmlInitParser();
  return 0;
}

void cleanup_rss(void) {
  xmlCleanupParser();
  curl_global_cleanup();
}

RssFeed *read_rss(const char *url) {
  struct RssResponse response = {0};
  RssFeed *feed;

  if (url == NULL || *url == '\0') {
    return NULL;
  }

  if (fetch(url, &response) != 0) {
    free(response.data);
    return NULL;
  }

  feed = parse_rss(response.data, response.length);
  free(response.data);
  return feed;
}

RssFeed *parse_rss(const char *xml, size_t length) {
  xmlDocPtr doc;
  RssFeed *feed;

  if (xml == NULL || length == 0 || length > INT_MAX) {
    return NULL;
  }

  /*
   * XML_PARSE_NONET prevents network access from the parser. Do not add
   * XML_PARSE_NOENT, XML_PARSE_DTDLOAD, or XML_PARSE_HUGE: feed data is
   * untrusted input.
   */
  doc = xmlReadMemory(xml, (int)length, "feed.xml", NULL,
                      XML_PARSE_NONET | XML_PARSE_RECOVER);
  if (doc == NULL) {
    return NULL;
  }

  feed = parse_document(doc);
  xmlFreeDoc(doc);
  return feed;
}

void free_rss(RssFeed *feed) {
  if (feed == NULL) {
    return;
  }

  free(feed->version);
  free(feed->channel.title);
  free(feed->channel.link);
  free(feed->channel.description);
  free(feed->channel.language);
  free(feed->channel.last_build_date);
  free(feed->channel.atom_link.href);
  free(feed->channel.atom_link.rel);
  free(feed->channel.atom_link.type);

  for (size_t i = 0; i < feed->item_count; i++) {
    RssItem *item = &feed->items[i];

    free(item->title);
    free(item->link);
    free(item->guid.value);
    free(item->pub_date);
    free(item->description);
    free(item->content_encoded);

    for (size_t j = 0; j < item->category_count; j++) {
      free(item->categories[j]);
    }
    free(item->categories);

    for (size_t j = 0; j < item->package_count; j++) {
      RssPackage *package = &item->packages[j];

      free(package->ecosystem);
      free(package->name);
      free(package->purl);
      free(package->introduced);
      free(package->fixed);
      free(package->last_affected);
      free(package->binaries);
      free(package->source);
      free(package->source_url);
    }
    free(item->packages);
  }

  free(feed->items);
  free(feed);
}
