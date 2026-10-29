// Native memory-safety harness. Compile with the unmodified official engine
// and grammars; see internal/dev/maintenance/treeparse_sanitize.py. Not linked into Scout.
#include "native.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const TSLanguage *tree_sitter_python(void);
const TSLanguage *tree_sitter_javascript(void);
const TSLanguage *tree_sitter_typescript(void);
const TSLanguage *tree_sitter_tsx(void);

// Track all engine allocations via its public allocator API. The independent
// platform leak detector also checks adapter, harness and scanner allocations.
typedef union { max_align_t alignment; size_t size; } Header;
static atomic_size_t live_blocks, live_bytes;
static void *tracked_malloc(size_t size) {
  assert(size <= SIZE_MAX - sizeof(Header));
  Header *h = malloc(sizeof(*h) + size);
  assert(h);
  h->size = size;
  atomic_fetch_add(&live_blocks, 1);
  atomic_fetch_add(&live_bytes, size);
  return h + 1;
}
static void tracked_free(void *ptr) {
  if (!ptr) return;
  Header *h = (Header *)ptr - 1;
  atomic_fetch_sub(&live_blocks, 1);
  atomic_fetch_sub(&live_bytes, h->size);
  free(h);
}
static void *tracked_calloc(size_t count, size_t size) {
  assert(!size || count <= SIZE_MAX / size);
  void *ptr = tracked_malloc(count * size);
  memset(ptr, 0, count * size);
  return ptr;
}
static void *tracked_realloc(void *ptr, size_t size) {
  if (!ptr) return tracked_malloc(size);
  if (!size) { tracked_free(ptr); return NULL; }
  assert(size <= SIZE_MAX - sizeof(Header));
  Header *h = (Header *)ptr - 1;
  size_t old = h->size;
  h = realloc(h, sizeof(*h) + size);
  assert(h);
  h->size = size;
  atomic_fetch_sub(&live_bytes, old);
  atomic_fetch_add(&live_bytes, size);
  return h + 1;
}

typedef struct {
  ScoutParser *parser;
  atomic_bool parsed;
  bool late;
  long delay_ns;
} Callback;

static void *cancel_callback(void *arg) {
  Callback *c = arg;
  if (c->late) {
    while (!atomic_load_explicit(&c->parsed, memory_order_acquire)) sched_yield();
  } else if (c->delay_ns) {
    struct timespec delay = {.tv_nsec = c->delay_ns};
    nanosleep(&delay, NULL);
  }
  scout_parser_cancel(c->parser);
  return NULL;
}

typedef struct {
  const TSLanguage *language;
  const char *valid;
  char *complex;
  size_t length;
  size_t rounds, trees, cancelled, callbacks, reused;
} Worker;

static char *complex_text(unsigned language) {
  size_t n = 1200;
  const char *prefix = language == 0 ? "" : "let x=";
  const char *open = language == 0 ? "([" : "A<";
  const char *end = language == 0 ? "}" : ">";
  char *text = calloc(1, n * 3 + 32);
  assert(text);
  strcpy(text, prefix);
  for (size_t i = 0; i < n; i++) strcat(text, open);
  if (language != 0) strcat(text, "T");
  for (size_t i = 0; i < n; i++) strcat(text, end);
  if (language != 0) strcat(text, ";\n");
  return text;
}

static void inspect_tree(TSTree *tree, size_t length) {
  TSNode root = ts_tree_root_node(tree);
  assert(ts_node_end_byte(root) == length);
  TSNode stack[2048];
  size_t count = 1, visited = 0;
  stack[0] = root;
  while (count && visited++ < 8192) {
    TSNode n = stack[--count];
    assert(ts_node_type(n) && strlen(ts_node_type(n)));
    assert(ts_node_start_byte(n) <= ts_node_end_byte(n));
    assert(ts_node_end_byte(n) <= length);
    (void)ts_node_is_named(n);
    (void)ts_node_is_error(n);
    (void)ts_node_is_missing(n);
    (void)ts_node_has_error(n);
    uint32_t children = ts_node_child_count(n);
    for (uint32_t i = 0; i < children && count < 2048; i++) {
      const char *field = ts_node_field_name_for_child(n, i);
      if (field) assert(strlen(field));
      stack[count++] = scout_node_child(n, i);
    }
  }
}

static void *worker_main(void *arg) {
  Worker *w = arg;
  for (size_t i = 0; i < w->rounds; i++) {
    ScoutParser *p = scout_parser_new();
    assert(p && scout_parser_language(p, w->language));
    unsigned mode = i % 6;
    const char *source = mode == 0 ? w->valid : w->complex;
    size_t length = strlen(source);
    char *input = malloc(length + 1);
    assert(input);
    memcpy(input, source, length + 1);
    assert(scout_parser_prepare(p, mode == 2 ? 1 : 5000000000ULL));
    if (mode == 3) scout_parser_cancel(p);
    Callback callback = {.parser = p, .late = mode == 5, .delay_ns = 150000};
    atomic_init(&callback.parsed, false);
    pthread_t thread;
    bool threaded = mode >= 4;
    if (threaded) assert(!pthread_create(&thread, NULL, cancel_callback, &callback));
    TSTree *tree = scout_parser_parse(p, input, length);
    atomic_store_explicit(&callback.parsed, true, memory_order_release);
    // Same lifetime rule as Go AfterFunc: join before reset/reuse/delete.
    if (threaded) { assert(!pthread_join(thread, NULL)); w->callbacks++; }
    free(input);
    if (mode == 2 || mode == 3) assert(!tree);
    if (tree) { w->trees++; inspect_tree(tree, length); }
    else w->cancelled++;
    scout_parser_reset(p);
    // A stale cancellation flag/callback must not affect the next request.
    assert(scout_parser_prepare(p, 5000000000ULL));
    char *next = strdup(w->valid);
    assert(next);
    TSTree *reused = scout_parser_parse(p, next, strlen(next));
    free(next);
    assert(reused && !ts_node_has_error(ts_tree_root_node(reused)));
    w->reused++;
    scout_parser_delete(p);
    // Native trees must survive both the parser and all input buffers.
    if (tree) { inspect_tree(tree, length); ts_tree_delete(tree); }
    inspect_tree(reused, strlen(w->valid));
    ts_tree_delete(reused);
  }
  return NULL;
}

static void leak_control(const TSLanguage *language) {
  ScoutParser *p = scout_parser_new();
  assert(p && scout_parser_language(p, language));
  // Intentional lost parser. Used only to verify the leak detector itself.
}

int main(int argc, char **argv) {
  atomic_init(&live_blocks, 0);
  atomic_init(&live_bytes, 0);
  ts_set_allocator(tracked_malloc, tracked_calloc, tracked_realloc, tracked_free);
  if (argc > 1 && !strcmp(argv[1], "--uaf-control")) {
    ScoutParser *p = scout_parser_new();
    scout_parser_delete(p);
    scout_parser_cancel(p); // Intentional ASan positive control.
    return 0;
  }
  if (argc > 1 && !strcmp(argv[1], "--leak-control")) {
    leak_control(tree_sitter_python());
    return 0;
  }
  size_t rounds = argc > 1 ? strtoul(argv[1], NULL, 10) : 500;
  assert(rounds > 0 && rounds <= 100000);
  Worker workers[4] = {
    {.language = tree_sitter_python(), .valid = "value = '🙂'\n"},
    {.language = tree_sitter_javascript(), .valid = "const value = '🙂';\n"},
    {.language = tree_sitter_typescript(), .valid = "let value: string = '🙂';\n"},
    {.language = tree_sitter_tsx(), .valid = "const value = <A text='🙂'/>;\n"},
  };
  pthread_t threads[4];
  for (unsigned i = 0; i < 4; i++) {
    workers[i].complex = complex_text(i);
    workers[i].rounds = rounds;
    assert(!pthread_create(&threads[i], NULL, worker_main, &workers[i]));
  }
  size_t trees = 0, cancelled = 0, callbacks = 0, reused = 0;
  for (unsigned i = 0; i < 4; i++) {
    assert(!pthread_join(threads[i], NULL));
    trees += workers[i].trees;
    cancelled += workers[i].cancelled;
    callbacks += workers[i].callbacks;
    reused += workers[i].reused;
    free(workers[i].complex);
  }
  size_t blocks = atomic_load(&live_blocks), bytes = atomic_load(&live_bytes);
  printf("rounds=%zu trees=%zu cancelled=%zu joined_callbacks=%zu reused=%zu engine_live_blocks=%zu engine_live_bytes=%zu\n", 4 * rounds, trees, cancelled, callbacks, reused, blocks, bytes);
  assert(!blocks && !bytes);
  return 0;
}
