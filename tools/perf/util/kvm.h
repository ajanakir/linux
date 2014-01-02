#ifndef _PERF_KVM_H_
#define _PERF_KVM_H_

int kvm__init(const char *cpuid);
const char *kvm__get_exit_reason(u64 exit_code);
bool kvm__is_hlt_exit(u64 exit_code);

#endif
