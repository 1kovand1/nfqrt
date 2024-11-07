#pragma once 
#include "uhash.h"

UHASH_INIT(stringHashSet, char*, void*, uhash_str_hash, uhash_str_equals);

void loadList(char const* path);
bool isInList(char const* sni);
void freeList(void);