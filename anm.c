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

int
add_anm(unsigned char *from, struct interface *ifp, unsigned int last_ts,
	unsigned short last_pc)
{
    struct anm *anm = find_anm(from, ifp);
    if(anm) {
        anm->last_ts = last_ts;
        anm->last_pc = last_pc;
        return 1;
    }

    if(numanms >= maxanms) {
        struct anm *new_anms;
        int n = maxanms < 1 ? 8 : 2 * maxanms;
        new_anms = realloc(anms, n * sizeof(struct anm));
        if(new_anms == NULL)
            return -1;
        maxanms = n;
        anms = new_anms;
    }

    memcpy(anms[numanms].from, from, 16);
    anms[numanms].ifp = ifp;
    anms[numanms].last_ts = last_ts;
    anms[numanms].last_pc = last_pc;
    numanms++;
    return 1;
}
