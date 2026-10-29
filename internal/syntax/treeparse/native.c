//go:build !coreonly && cgo

#include "native.h"
#include <stdatomic.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

struct ScoutParser {
  TSParser *parser;
  atomic_bool cancelled;
  uint64_t deadline_ns;
  bool interrupted;
  const char *text;
  uint32_t length;
};

// Clock failure aborts parsing, never removes its limit.
static bool monotonic_ns(uint64_t *result) {
#ifdef _WIN32
  LARGE_INTEGER count, frequency;
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&count) ||
      frequency.QuadPart <= 0 || count.QuadPart < 0) return false;
  uint64_t ticks = (uint64_t)count.QuadPart;
  uint64_t hz = (uint64_t)frequency.QuadPart;
  *result = (ticks / hz) * 1000000000ULL +
            (uint64_t)((long double)(ticks % hz) * 1000000000ULL / hz);
#else
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
  *result = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
#endif
  return true;
}

static bool interrupted(ScoutParser *parser) {
  uint64_t now;
  if (atomic_load_explicit(&parser->cancelled, memory_order_relaxed) ||
      !monotonic_ns(&now) || now >= parser->deadline_ns)
    parser->interrupted = true;
  return parser->interrupted;
}

static bool progress(TSParseState *state) { return interrupted(state->payload); }

static const char *read_input(void *payload, uint32_t offset, TSPoint point,
                              uint32_t *bytes_read) {
  (void)point;
  ScoutParser *parser = payload;
  *bytes_read = 0;
  if (interrupted(parser) || offset >= parser->length) return NULL;
  uint32_t remaining = parser->length - offset;
  *bytes_read = remaining < 4096 ? remaining : 4096;
  return parser->text + offset;
}

ScoutParser *scout_parser_new(void) {
  ScoutParser *parser = calloc(1, sizeof(*parser));
  if (!parser) return NULL;
  parser->parser = ts_parser_new();
  if (!parser->parser) { free(parser); return NULL; }
  atomic_init(&parser->cancelled, false);
  return parser;
}

void scout_parser_delete(ScoutParser *parser) {
  if (!parser) return;
  ts_parser_delete(parser->parser);
  free(parser);
}

bool scout_parser_language(ScoutParser *parser, const TSLanguage *language) {
  return parser && ts_parser_set_language(parser->parser, language);
}

void scout_parser_reset(ScoutParser *parser) { ts_parser_reset(parser->parser); }

bool scout_parser_prepare(ScoutParser *parser, uint64_t remaining_ns) {
  uint64_t now;
  if (!monotonic_ns(&now) || !remaining_ns || remaining_ns > UINT64_MAX - now)
    return false;
  atomic_store_explicit(&parser->cancelled, false, memory_order_relaxed);
  parser->interrupted = false;
  parser->deadline_ns = now + remaining_ns;
  return true;
}

void scout_parser_cancel(ScoutParser *parser) {
  atomic_store_explicit(&parser->cancelled, true, memory_order_relaxed);
}

TSTree *scout_parser_parse(ScoutParser *parser, const char *text, size_t length) {
  if (length > UINT32_MAX) return NULL;
  parser->text = text;
  parser->length = (uint32_t)length;
  TSInput input = { .payload = parser, .read = read_input,
                    .encoding = TSInputEncodingUTF8, .decode = NULL };
  TSParseOptions options = { .payload = parser, .progress_callback = progress };
  TSTree *tree = ts_parser_parse_with_options(parser->parser, NULL, input, options);
  if (interrupted(parser)) { ts_tree_delete(tree); tree = NULL; }
  // v0.25.0 reset clears finished_tree but leaves canceled_balancing set.
  // Reuse after cancellation during balancing would then assert on a missing
  // tree (upstream tree-sitter/tree-sitter#4176). Replace the engine, retaining
  // the language before deleting its old owner. Callback state stays here so
  // an in-flight Go cancellation callback still targets a live ScoutParser.
  if (!tree) {
    TSParser *fresh = ts_parser_new();
    ts_parser_set_language(fresh, ts_parser_language(parser->parser));
    ts_parser_delete(parser->parser);
    parser->parser = fresh;
  }
  // No borrowed Go input pointer survives this synchronous C call.
  parser->text = NULL;
  parser->length = 0;
  return tree;
}

TSNode scout_node_child(TSNode node, size_t index) {
  if (index > UINT32_MAX) return (TSNode){0};
  return ts_node_child(node, (uint32_t)index);
}
