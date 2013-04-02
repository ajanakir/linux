ifdef CONFIG_DWARF
PERF_HAVE_DWARF_REGS := 1
LIB_OBJS += $(OUTPUT)arch/$(ARCH)/util/dwarf-regs.o
endif
ifdef CONFIG_LIBUNWIND
LIB_OBJS += $(OUTPUT)arch/$(ARCH)/util/unwind.o
endif
LIB_OBJS += $(OUTPUT)arch/$(ARCH)/util/header.o
