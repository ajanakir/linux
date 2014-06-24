#ifndef _PERF_KVM_H_
#define _PERF_KVM_H_

#if defined(__i386__) || defined(__x86_64__)
int kvm__init(const char *cpuid);
const char *kvm__get_exit_reason(u64 exit_code);
bool kvm__is_hlt_exit(u64 exit_code);
#else
static inline int kvm__init(const char *cpuid __maybe_unused)
{
	return 0;
}
#endif

#endif
