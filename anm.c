#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "babeld.h"
#include "kernel.h"
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "anm.h"
#include "util.h"
#include "configuration.h"
#include "local.h"

static struct anm *anms;
static int numanms = 0, maxanms = 0;

struct anm *
find_anm(const unsigned char *from, const struct interface *ifp)
{
    int i;
    for(i = 0; i < numanms; i++) {
      if(memcmp(anms[i].from, from, 16) == 0 && anms[i].ifp == ifp)
            return &anms[i];
    }
    return NULL;
}

struct anm *
add_anm(const unsigned char *from, struct interface *ifp,
	unsigned char *last_tspc)
{
    struct anm *anm = find_anm(from, ifp);
    if(anm) {
        memcpy(anm->last_tspc, last_tspc, 6);
        return anm;
    }

    if(numanms >= maxanms) {
        struct anm *new_anms;
        int n = maxanms < 1 ? 8 : 2 * maxanms;
        new_anms = realloc(anms, n * sizeof(struct anm));
        if(new_anms == NULL)
            return NULL;
        maxanms = n;
        anms = new_anms;
    }

    memcpy(anms[numanms].from, from, 16);
    anms[numanms].ifp = ifp;
    memcpy(anms[numanms].last_tspc, last_tspc, 6);
    numanms++;
    return &anms[numanms - 1];
}
