#include <asm/svm.h>
#include <asm/vmx.h>
#include <asm/kvm.h>
#include <errno.h>
#include <linux/kernel.h>
#include "util/header.h"
#include "util/kvm.h"
#include "util/util.h"

struct exit_reasons_table {
	unsigned long exit_code;
	const char *reason;
};

static struct exit_reasons_table *exit_reasons;
static int exit_reasons_size;
static const char *exit_reasons_isa;

static struct exit_reasons_table vmx_exit_reasons[] = {
	VMX_EXIT_REASONS
};

static struct exit_reasons_table svm_exit_reasons[] = {
	SVM_EXIT_REASONS
};

const char *kvm__get_exit_reason(u64 exit_code)
{
	int i = exit_reasons_size;
	struct exit_reasons_table *tbl = exit_reasons;

	while (i--) {
		if (tbl->exit_code == exit_code)
			return tbl->reason;
		tbl++;
	}

	pr_err("unknown kvm exit code:%lld on %s\n",
		(unsigned long long)exit_code, exit_reasons_isa);
	return "UNKNOWN";
}

bool kvm__is_hlt_exit(u64 exit_code)
{
	bool rc;

	if (exit_reasons == vmx_exit_reasons)
		rc = exit_code == EXIT_REASON_HLT;
	else
		rc = exit_code == SVM_EXIT_HLT;

	return rc;
}

int kvm__init(const char *cpuid)
{
	char buf[64];
	int err, isa;

	if (cpuid == NULL) {
		err = get_cpuid(buf, sizeof(buf));
		if (err != 0) {
			pr_err("Failed to look up CPU type (Intel or AMD)\n");
			return err;
		}
		cpuid = buf;
	}

	if (strstr(cpuid, "Intel"))
		isa = 1;
	else if (strstr(cpuid, "AMD"))
		isa = 0;
	else {
		pr_err("CPU %s is not supported.\n", cpuid);
		return -ENOTSUP;
	}

	if (isa == 1) {
		exit_reasons = vmx_exit_reasons;
		exit_reasons_size = ARRAY_SIZE(vmx_exit_reasons);
		exit_reasons_isa = "VMX";
	} else {
		exit_reasons = svm_exit_reasons;
		exit_reasons_size = ARRAY_SIZE(svm_exit_reasons);
		exit_reasons_isa = "SVM";
	}

	return 0;
}
