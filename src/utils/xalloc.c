#include <err.h>
#include <stdlib.h>

#include "xalloc.h"


void *xmalloc(size_t size)
{
    void *ret = malloc(size);
    if (size && !ret)
        err(1, "Failed to malloc");
    return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
    void *ret = calloc(nmemb, size);
    if ((nmemb * size != 0) && !ret)
        err(1, "Failed to calloc");
    return ret;
}
