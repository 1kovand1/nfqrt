#include "uhash.h"
#include "hostlist.h"
#include <stdio.h>

UHash_stringHashSet* snis;

void loadList(char const *path)
{
    snis = uhset_alloc_stringHashSet();

    FILE* fd = fopen(path, "r");
    char buf[256];
    while (fgets(buf, 256, fd))
    {
        size_t len = strlen(buf);
        char* sni;
        if (len == 0)
            continue;
        if (buf[len-1] == '\n')
        {
            sni = malloc(len);
            strncpy(sni, buf, len - 1);
            sni[len-1] = '\0';
        }
        else
        {
            sni = malloc(len + 1);
            strcpy(sni, buf);
            sni[len] = '\0';
        }
        uhash_put_stringHashSet(snis, sni, NULL);
    }

    fclose(fd);
}

bool isInList(char const *sni)
{
    return uhash_contains(stringHashSet, snis, sni);
}

void freeList(void)
{
    uhash_foreach_key(stringHashSet, snis, sni, free(sni));
    uhash_free_stringHashSet(snis);
}
