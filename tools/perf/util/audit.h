#ifndef _PERF_AUDIT_H_
#define _PERF_AUDIT_H_

struct thread;
struct map;

#ifdef HAVE_LIBAUDIT_SUPPORT
#include "libaudit.h"

void audit_machine__init_thread(struct thread *thread);
void audit_machine__fork_thread(struct thread *t, struct thread *p);
void audit_machine__update_thread(struct thread *thread, struct map *map);
static inline int audit_machine__from_thread(struct thread *thread)
{
	return thread->audit_machine;
}

#else

static inline void audit_machine__init_thread(struct thread *thread)
{
}
static inline
void audit_machine__fork_thread(struct thread *t, struct thread *p)
{
}
static inline
void audit_machine__update_thread(struct thread *thread, struct map *map)
{
}
#endif
#endif
