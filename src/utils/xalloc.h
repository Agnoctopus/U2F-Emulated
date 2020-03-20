#ifndef XALLOC_H
#define XALLOC_H

#include <stddef.h>


#define ATTR(Att) __attribute__((Att))
#define __malloc ATTR(malloc)

/**
** \brief Safe malloc wrapper
** \param size The size to allocate
** \return a pointer to the allocated memory
*/
void *xmalloc(size_t size) __malloc;

/**
** \brief Safe calloc wrapper
** \param nmemb The number of member
** \param size The size of each member
** \return a pointer to the allocated memory
*/
void *xcalloc(size_t nmemb, size_t size);

#endif
