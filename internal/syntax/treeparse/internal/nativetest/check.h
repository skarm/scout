#ifndef SCOUT_TREEPARSE_TEST_CHECK_H
#define SCOUT_TREEPARSE_TEST_CHECK_H
#include "tree_sitter_api.h"
#include <stddef.h>

const char *scout_test_progress(const TSLanguage *language, const char *text,
                                size_t length, const char *event, bool deadline);
#endif
