#ifndef __CR_SMAPS_PREFETCH_H__
#define __CR_SMAPS_PREFETCH_H__

#include <stddef.h>
#include <sys/types.h>

int smaps_prefetch_start(void);
void smaps_prefetch_network_done(void);
/* 1 transfers a complete input to the caller; 0 keeps the ordinary input. */
int smaps_prefetch_take(pid_t pid, char **text, size_t *length);
int smaps_prefetch_cleanup(void);

#endif
