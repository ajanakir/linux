#include "thread.h"
#include "map.h"
#include "audit.h"

static int audit_machine = -1;

void audit_machine__init_thread(struct thread *thread)
{
	/* cache default audit machine -- based on running kernel */
	if (audit_machine == -1)
		audit_machine = audit_detect_machine();

	thread->audit_machine = audit_machine;
}

void audit_machine__fork_thread(struct thread *t, struct thread *p)
{
	t->audit_machine = p->audit_machine;
}

void audit_machine__update_thread(struct thread *thread, struct map *map)
{
	bool is_64;

	/* 64-bit kernel can run 32-bit apps, but not vice versa */
	/* TO-DO: how to handle arm and ppc */
	if (audit_machine == MACH_X86)
		return;

	is_64 = dso_is_64bit(map->dso);
	if (is_64 < 0)
		return;

	if (!is_64)
		thread->audit_machine = MACH_X86;
}
