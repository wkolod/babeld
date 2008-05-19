/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "babel.h"
#include "util.h"
#include "source.h"
#include "network.h"
#include "route.h"

struct source srcs[MAXSRCS];
int numsrcs = 0;

struct source *
find_source(const unsigned char *id, const unsigned char *p, unsigned char plen,
            int create, unsigned short seqno)
{
    struct source *src;
    int i, rc;

    for(i = 0; i < numsrcs; i++) {
        if(!srcs[i].valid)
            continue;
        /* This should really be a hash table.  For now, check the
           last byte first. */
        if(srcs[i].id[15] != id[15])
            continue;
        if(memcmp(srcs[i].id, id, 16) != 0)
            continue;
        if(source_match(&srcs[i], p, plen))
           return &srcs[i];
    }

    if(!create)
        return NULL;

 again:

    src = NULL;

    for(i = 0; i < numsrcs; i++) {
        if(srcs[i].valid == 0) {
            src = &srcs[i];
            break;
        }
    }

    if(!src) {
        if(numsrcs >= MAXSRCS) {
            rc = expire_sources();
            if(rc)
                goto again;
            fprintf(stderr, "Too many sources.\n");
            return NULL;
        }
        src = &srcs[numsrcs++];
    }

    src->valid = 1;
    memcpy(src->id, id, 16);
    memcpy(src->prefix, p, 16);
    src->plen = plen;
    src->seqno = seqno;
    src->metric = INFINITY;
    src->time = now.tv_sec;
    return src;
}

int
flush_source(struct source *src)
{
    int i;

    for(i = 0; i < numroutes; i++) {
        if(routes[i].src == src)
            return 0;
    }

    memset(src, 0, sizeof(*src));
    VALGRIND_MAKE_MEM_UNDEFINED(src, sizeof(*src));
    src->valid = 0;

    while(numsrcs > 0 && !srcs[numsrcs - 1].valid) {
        numsrcs--;
        VALGRIND_MAKE_MEM_UNDEFINED(&srcs[numsrcs], sizeof(srcs[numsrcs]));
    }

    return 1;
}

int
source_match(struct source *src,
             const unsigned char *p, unsigned char plen)
{
    if(src->plen != plen)
        return 0;
    if(src->prefix[15] != p[15])
        return 0;
    if(memcmp(src->prefix, p, 16) != 0)
        return 0;
    return 1;
}

void
update_source(struct source *src,
              unsigned short seqno, unsigned short metric)
{
    if(metric >= INFINITY)
        return;

    if(src->time < now.tv_sec - SOURCE_GC_TIME ||
       seqno_compare(src->seqno, seqno) < 0 ||
       (src->seqno == seqno && src->metric > metric)) {
        src->seqno = seqno;
        src->metric = metric;
    }
    src->time = now.tv_sec;
}

int
expire_sources()
{
    int i, changed, rc;

    changed = 0;

    for(i = 0; i < numsrcs; i++) {
        if(!srcs[i].valid)
            continue;
        if(srcs[i].time > now.tv_sec)
            /* clock stepped */
            srcs[i].time = now.tv_sec;
        if(srcs[i].time < now.tv_sec - SOURCE_GC_TIME) {
            rc = flush_source(&srcs[i]);
            changed = changed || rc;
        }
    }

    return changed;
}
