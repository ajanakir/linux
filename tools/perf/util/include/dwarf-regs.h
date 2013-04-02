#ifndef _PERF_DWARF_REGS_H_
#define _PERF_DWARF_REGS_H_

#include <linux/kconfig.h>

#ifdef CONFIG_DWARF
const char *get_arch_regstr(unsigned int n);
#endif

#endif
