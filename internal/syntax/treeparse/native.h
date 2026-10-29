#ifndef SCOUT_TREEPARSE_NATIVE_H
#define SCOUT_TREEPARSE_NATIVE_H
// Unmodified public header from official go-tree-sitter v0.25.0.
// The engine is linked from that module, not copied here.
#include "tree_sitter_api.h"
typedef struct ScoutParser ScoutParser;
ScoutParser *scout_parser_new(void);
void scout_parser_delete(ScoutParser *parser);
bool scout_parser_language(ScoutParser *parser, const TSLanguage *language);
void scout_parser_reset(ScoutParser *parser);
bool scout_parser_prepare(ScoutParser *parser, uint64_t remaining_ns);
void scout_parser_cancel(ScoutParser *parser);
TSTree *scout_parser_parse(ScoutParser *parser, const char *text, size_t length);
TSNode scout_node_child(TSNode node, size_t index);
#endif
