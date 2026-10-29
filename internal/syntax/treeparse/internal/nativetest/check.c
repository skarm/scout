//go:build !coreonly && cgo

#include "check.h"
#include <string.h>

// Compile the actual adapter under private names. Only Go tests import this
// package; no instrumentation or extra copy of the adapter enters Scout.
#define scout_parser_new test_parser_new
#define scout_parser_delete test_parser_delete
#define scout_parser_language test_parser_language
#define scout_parser_reset test_parser_reset
#define scout_parser_prepare test_parser_prepare
#define scout_parser_cancel test_parser_cancel
#define scout_parser_parse test_parser_parse
#define scout_node_child test_node_child
#ifndef SCOUT_TREEPARSE_ADAPTER
#define SCOUT_TREEPARSE_ADAPTER "../../native.c"
#endif
#include SCOUT_TREEPARSE_ADAPTER

typedef struct {
  ScoutParser *parser;
  const char *event;
  bool armed, deadline, triggered, accepted, completed;
} Checkpoint;

static void interrupt_at_checkpoint(void *payload, TSLogType type,
                                     const char *message) {
  if (type != TSLogTypeParse) return;
  Checkpoint *checkpoint = payload;
  if (!strcmp(message, "accept")) checkpoint->accepted = true;
  if (!strcmp(message, "done")) checkpoint->completed = true;
  if (!checkpoint->armed || checkpoint->triggered ||
      strncmp(message, checkpoint->event, strlen(checkpoint->event))) return;
  checkpoint->triggered = true;
  if (checkpoint->deadline) checkpoint->parser->deadline_ns = 0;
  else scout_parser_cancel(checkpoint->parser);
}

static bool complete_tree(TSTree *tree, size_t length) {
  if (!tree) return false;
  TSNode root = ts_tree_root_node(tree);
  return !ts_node_has_error(root) && ts_node_end_byte(root) == length;
}

const char *scout_test_progress(const TSLanguage *language, const char *text,
                                size_t length, const char *event, bool deadline) {
  const char *failure = NULL;
  TSTree *tree = NULL;
  ScoutParser *parser = scout_parser_new();
  if (!parser || !scout_parser_language(parser, language)) {
    failure = "cannot create reference parser";
    goto done;
  }
  Checkpoint checkpoint = {.parser = parser};
  ts_parser_set_logger(parser->parser, (TSLogger){&checkpoint, interrupt_at_checkpoint});
  if (!scout_parser_prepare(parser, 3600000000000ULL)) {
    failure = "cannot prepare reference parse";
    goto done;
  }
  tree = scout_parser_parse(parser, text, length);
  if (!complete_tree(tree, length) || !checkpoint.completed) {
    failure = "reference parse did not reach a complete tree";
    goto done;
  }
  ts_tree_delete(tree);
  tree = NULL;
  scout_parser_reset(parser);
  checkpoint = (Checkpoint){.parser = parser, .event = event, .armed = true, .deadline = deadline};
  if (!scout_parser_prepare(parser, 3600000000000ULL)) {
    failure = "cannot prepare interrupted parse";
    goto done;
  }
  tree = scout_parser_parse(parser, text, length);
  if (!checkpoint.triggered || tree || checkpoint.completed ||
      (strcmp(event, "accept") && checkpoint.accepted)) {
    failure = "native work completed instead of stopping at the checkpoint";
    goto done;
  }
  // The interrupted stack must not survive into the next request.
  const char *next = "let answer = 42;\n";
  ts_parser_set_logger(parser->parser, (TSLogger){0});
  if (!scout_parser_prepare(parser, 3600000000000ULL)) {
    failure = "cannot prepare parser reuse";
    goto done;
  }
  tree = scout_parser_parse(parser, next, strlen(next));
  if (!complete_tree(tree, strlen(next)))
    failure = "interruption contaminated the next parse";
done:
  ts_tree_delete(tree);
  scout_parser_delete(parser);
  return failure;
}
