#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/evlist.h"
#include "util/cache.h"
#include "util/evsel.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/stat.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"

#include "util/strlist.h"
#include "util/intlist.h"
#include "util/time-utils.h"
#include "util/kvm.h"
#include "asm/bug.h"
#include <sys/prctl.h>
#include <sys/resource.h>

#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/vmx.h>
#endif

#define PR_SET_NAME		15               /* Set process name */
#define MAX_CPUS		4096
#define COMM_LEN		20
#define SYM_LEN			129
#define MAX_PID			65536

struct sched_atom;

struct task_desc {
	unsigned long		nr;
	unsigned long		pid;
	char			comm[COMM_LEN];

	unsigned long		nr_events;
	unsigned long		curr_event;
	struct sched_atom	**atoms;

	pthread_t		thread;
	sem_t			sleep_sem;

	sem_t			ready_for_work;
	sem_t			work_done_sem;

	u64			cpu_usage;
};

enum sched_event_type {
	SCHED_EVENT_RUN,
	SCHED_EVENT_SLEEP,
	SCHED_EVENT_WAKEUP,
	SCHED_EVENT_MIGRATION,
};

struct sched_atom {
	enum sched_event_type	type;
	int			specific_wait;
	u64			timestamp;
	u64			duration;
	unsigned long		nr;
	sem_t			*wait_sem;
	struct task_desc	*wakee;
};

#define TASK_STATE_TO_CHAR_STR "RSDTtZX"

enum thread_state {
	THREAD_SLEEPING = 0,
	THREAD_WAIT_CPU,
	THREAD_SCHED_IN,
	THREAD_IGNORE
};

struct work_atom {
	struct list_head	list;
	enum thread_state	state;
	u64			sched_out_time;
	u64			wake_up_time;
	u64			sched_in_time;
	u64			runtime;
};

struct work_atoms {
	struct list_head	work_list;
	struct thread		*thread;
	struct rb_node		node;
	u64			max_lat;
	u64			max_lat_at;
	u64			total_lat;
	u64			nb_atoms;
	u64			total_runtime;
};

typedef int (*sort_fn_t)(struct work_atoms *, struct work_atoms *);

struct perf_sched;

struct trace_sched_handler {
	int (*switch_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine);

	int (*runtime_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			     struct perf_sample *sample, struct machine *machine);

	int (*wakeup_event)(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine);

	/* PERF_RECORD_FORK event, not sched_process_fork tracepoint */
	int (*fork_event)(struct perf_sched *sched, union perf_event *event,
			  struct machine *machine);

	int (*migrate_task_event)(struct perf_sched *sched,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct machine *machine);
};

struct perf_sched {
	struct perf_tool tool;
	const char	 *sort_order;
	unsigned long	 nr_tasks;
	struct task_desc *pid_to_task[MAX_PID];
	struct task_desc **tasks;
	const struct trace_sched_handler *tp_handler;
	pthread_mutex_t	 start_work_mutex;
	pthread_mutex_t	 work_done_wait_mutex;
	int		 profile_cpu;
/*
 * Track the current task - that way we can know whether there's any
 * weird events, such as a task being switched away that is not current.
 */
	int		 max_cpu;
	u32		 curr_pid[MAX_CPUS];
	struct thread	 *curr_thread[MAX_CPUS];
	char		 next_shortname1;
	char		 next_shortname2;
	unsigned int	 replay_repeat;
	unsigned long	 nr_run_events;
	unsigned long	 nr_sleep_events;
	unsigned long	 nr_wakeup_events;
	unsigned long	 nr_sleep_corrections;
	unsigned long	 nr_run_events_optimized;
	unsigned long	 targetless_wakeups;
	unsigned long	 multitarget_wakeups;
	unsigned long	 nr_runs;
	unsigned long	 nr_timestamps;
	unsigned long	 nr_unordered_timestamps;
	unsigned long	 nr_state_machine_bugs;
	unsigned long	 nr_context_switch_bugs;
	unsigned long	 nr_events;
	unsigned long	 nr_lost_chunks;
	unsigned long	 nr_lost_events;
	u64		 run_measurement_overhead;
	u64		 sleep_measurement_overhead;
	u64		 start_time;
	u64		 cpu_usage;
	u64		 runavg_cpu_usage;
	u64		 parent_cpu_usage;
	u64		 runavg_parent_cpu_usage;
	u64		 sum_runtime;
	u64		 sum_fluct;
	u64		 run_avg;
	u64		 all_runtime;
	u64		 all_count;
	u64		 cpu_last_switched[MAX_CPUS];
	struct rb_root	 atom_root, sorted_atom_root;
	struct list_head sort_list, cmp_pid;

	/* options for timehist command */
	FILE		*fp;
	bool		summary;
	bool		summary_only;
	bool		show_callchain;
	unsigned int	max_stack;
	bool		show_cpu_visual;
	bool		show_wakeups;
	bool		show_migrations;
	bool		pstree;
	bool		pstree_only;
	bool		have_traces;
	/* process and task id's of interest */
	struct target	target;
	struct intlist	*pid, *tid;
	const char	*time_str;
	struct perf_time ptime;
};

/* used in symbol filter */
static const char	*excl_sym_list_str;
static struct strlist	*excl_sym_list;

/* per thread run time data */
struct thread_runtime {
	struct list_head children;
	struct list_head node;

	struct thread *thread; /* link back to thread struct; for pstree */

	u64 last_time;      /* time of previous sched in/out event */
	u64 dt_run;         /* run time */
	u64 dt_between;     /* time between CPU access (off cpu) */
	u64 dt_delay;       /* time between wakeup and sched-in */
	u64 ready_to_run;   /* time of wakeup */

#if defined(__i386__) || defined(__x86_64__)
	bool in_guest;      /* true when task is in guest mode */
	bool exit_hlt;      /* exit reason is a cpu hlt */
	u64 last_time_kvm;  /* track kvm_entry/exit times */
#endif

	struct stats run_stats;
	u64 total_run_time;

	u64 migrations;
};

/* per event run time data */
struct evsel_runtime {
	u64 *last_time; /* time this event was last seen per cpu */
	u32 ncpu;       /* highest cpu slot allocated */
};

/* track idle times per cpu */
static struct thread **idle_threads;
static int idle_max_cpu;
static char idle_comm[] = "<idle>";

static u64 get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void burn_nsecs(struct perf_sched *sched, u64 nsecs)
{
	u64 T0 = get_nsecs(), T1;

	do {
		T1 = get_nsecs();
	} while (T1 + sched->run_measurement_overhead < T0 + nsecs);
}

static void sleep_nsecs(u64 nsecs)
{
	struct timespec ts;

	ts.tv_nsec = nsecs % 999999999;
	ts.tv_sec = nsecs / 999999999;

	nanosleep(&ts, NULL);
}

static void calibrate_run_measurement_overhead(struct perf_sched *sched)
{
	u64 T0, T1, delta, min_delta = 1000000000ULL;
	int i;

	for (i = 0; i < 10; i++) {
		T0 = get_nsecs();
		burn_nsecs(sched, 0);
		T1 = get_nsecs();
		delta = T1-T0;
		min_delta = min(min_delta, delta);
	}
	sched->run_measurement_overhead = min_delta;

	printf("run measurement overhead: %" PRIu64 " nsecs\n", min_delta);
}

static void calibrate_sleep_measurement_overhead(struct perf_sched *sched)
{
	u64 T0, T1, delta, min_delta = 1000000000ULL;
	int i;

	for (i = 0; i < 10; i++) {
		T0 = get_nsecs();
		sleep_nsecs(10000);
		T1 = get_nsecs();
		delta = T1-T0;
		min_delta = min(min_delta, delta);
	}
	min_delta -= 10000;
	sched->sleep_measurement_overhead = min_delta;

	printf("sleep measurement overhead: %" PRIu64 " nsecs\n", min_delta);
}

static struct sched_atom *
get_new_event(struct task_desc *task, u64 timestamp)
{
	struct sched_atom *event = zalloc(sizeof(*event));
	unsigned long idx = task->nr_events;
	size_t size;

	event->timestamp = timestamp;
	event->nr = idx;

	task->nr_events++;
	size = sizeof(struct sched_atom *) * task->nr_events;
	task->atoms = realloc(task->atoms, size);
	BUG_ON(!task->atoms);

	task->atoms[idx] = event;

	return event;
}

static struct sched_atom *last_event(struct task_desc *task)
{
	if (!task->nr_events)
		return NULL;

	return task->atoms[task->nr_events - 1];
}

static void add_sched_event_run(struct perf_sched *sched, struct task_desc *task,
				u64 timestamp, u64 duration)
{
	struct sched_atom *event, *curr_event = last_event(task);

	/*
	 * optimize an existing RUN event by merging this one
	 * to it:
	 */
	if (curr_event && curr_event->type == SCHED_EVENT_RUN) {
		sched->nr_run_events_optimized++;
		curr_event->duration += duration;
		return;
	}

	event = get_new_event(task, timestamp);

	event->type = SCHED_EVENT_RUN;
	event->duration = duration;

	sched->nr_run_events++;
}

static void add_sched_event_wakeup(struct perf_sched *sched, struct task_desc *task,
				   u64 timestamp, struct task_desc *wakee)
{
	struct sched_atom *event, *wakee_event;

	event = get_new_event(task, timestamp);
	event->type = SCHED_EVENT_WAKEUP;
	event->wakee = wakee;

	wakee_event = last_event(wakee);
	if (!wakee_event || wakee_event->type != SCHED_EVENT_SLEEP) {
		sched->targetless_wakeups++;
		return;
	}
	if (wakee_event->wait_sem) {
		sched->multitarget_wakeups++;
		return;
	}

	wakee_event->wait_sem = zalloc(sizeof(*wakee_event->wait_sem));
	sem_init(wakee_event->wait_sem, 0, 0);
	wakee_event->specific_wait = 1;
	event->wait_sem = wakee_event->wait_sem;

	sched->nr_wakeup_events++;
}

static void add_sched_event_sleep(struct perf_sched *sched, struct task_desc *task,
				  u64 timestamp, u64 task_state __maybe_unused)
{
	struct sched_atom *event = get_new_event(task, timestamp);

	event->type = SCHED_EVENT_SLEEP;

	sched->nr_sleep_events++;
}

static struct task_desc *register_pid(struct perf_sched *sched,
				      unsigned long pid, const char *comm)
{
	struct task_desc *task;

	BUG_ON(pid >= MAX_PID);

	task = sched->pid_to_task[pid];

	if (task)
		return task;

	task = zalloc(sizeof(*task));
	task->pid = pid;
	task->nr = sched->nr_tasks;
	strcpy(task->comm, comm);
	/*
	 * every task starts in sleeping state - this gets ignored
	 * if there's no wakeup pointing to this sleep state:
	 */
	add_sched_event_sleep(sched, task, 0, 0);

	sched->pid_to_task[pid] = task;
	sched->nr_tasks++;
	sched->tasks = realloc(sched->tasks, sched->nr_tasks * sizeof(struct task_task *));
	BUG_ON(!sched->tasks);
	sched->tasks[task->nr] = task;

	if (verbose)
		printf("registered task #%ld, PID %ld (%s)\n", sched->nr_tasks, pid, comm);

	return task;
}


static void print_task_traces(struct perf_sched *sched)
{
	struct task_desc *task;
	unsigned long i;

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		printf("task %6ld (%20s:%10ld), nr_events: %ld\n",
			task->nr, task->comm, task->pid, task->nr_events);
	}
}

static void add_cross_task_wakeups(struct perf_sched *sched)
{
	struct task_desc *task1, *task2;
	unsigned long i, j;

	for (i = 0; i < sched->nr_tasks; i++) {
		task1 = sched->tasks[i];
		j = i + 1;
		if (j == sched->nr_tasks)
			j = 0;
		task2 = sched->tasks[j];
		add_sched_event_wakeup(sched, task1, 0, task2);
	}
}

static void perf_sched__process_event(struct perf_sched *sched,
				      struct sched_atom *atom)
{
	int ret = 0;

	switch (atom->type) {
		case SCHED_EVENT_RUN:
			burn_nsecs(sched, atom->duration);
			break;
		case SCHED_EVENT_SLEEP:
			if (atom->wait_sem)
				ret = sem_wait(atom->wait_sem);
			BUG_ON(ret);
			break;
		case SCHED_EVENT_WAKEUP:
			if (atom->wait_sem)
				ret = sem_post(atom->wait_sem);
			BUG_ON(ret);
			break;
		case SCHED_EVENT_MIGRATION:
			break;
		default:
			BUG_ON(1);
	}
}

static u64 get_cpu_usage_nsec_parent(void)
{
	struct rusage ru;
	u64 sum;
	int err;

	err = getrusage(RUSAGE_SELF, &ru);
	BUG_ON(err);

	sum =  ru.ru_utime.tv_sec*1e9 + ru.ru_utime.tv_usec*1e3;
	sum += ru.ru_stime.tv_sec*1e9 + ru.ru_stime.tv_usec*1e3;

	return sum;
}

static int self_open_counters(void)
{
	struct perf_event_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));

	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_TASK_CLOCK;

	fd = sys_perf_event_open(&attr, 0, -1, -1, 0);

	if (fd < 0)
		pr_err("Error: sys_perf_event_open() syscall returned "
		       "with %d (%s)\n", fd, strerror(errno));
	return fd;
}

static u64 get_cpu_usage_nsec_self(int fd)
{
	u64 runtime;
	int ret;

	ret = read(fd, &runtime, sizeof(runtime));
	BUG_ON(ret != sizeof(runtime));

	return runtime;
}

struct sched_thread_parms {
	struct task_desc  *task;
	struct perf_sched *sched;
};

static void *thread_func(void *ctx)
{
	struct sched_thread_parms *parms = ctx;
	struct task_desc *this_task = parms->task;
	struct perf_sched *sched = parms->sched;
	u64 cpu_usage_0, cpu_usage_1;
	unsigned long i, ret;
	char comm2[22];
	int fd;

	free(parms);

	sprintf(comm2, ":%s", this_task->comm);
	prctl(PR_SET_NAME, comm2);
	fd = self_open_counters();
	if (fd < 0)
		return NULL;
again:
	ret = sem_post(&this_task->ready_for_work);
	BUG_ON(ret);
	ret = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(ret);
	ret = pthread_mutex_unlock(&sched->start_work_mutex);
	BUG_ON(ret);

	cpu_usage_0 = get_cpu_usage_nsec_self(fd);

	for (i = 0; i < this_task->nr_events; i++) {
		this_task->curr_event = i;
		perf_sched__process_event(sched, this_task->atoms[i]);
	}

	cpu_usage_1 = get_cpu_usage_nsec_self(fd);
	this_task->cpu_usage = cpu_usage_1 - cpu_usage_0;
	ret = sem_post(&this_task->work_done_sem);
	BUG_ON(ret);

	ret = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(ret);
	ret = pthread_mutex_unlock(&sched->work_done_wait_mutex);
	BUG_ON(ret);

	goto again;
}

static void create_tasks(struct perf_sched *sched)
{
	struct task_desc *task;
	pthread_attr_t attr;
	unsigned long i;
	int err;

	err = pthread_attr_init(&attr);
	BUG_ON(err);
	err = pthread_attr_setstacksize(&attr,
			(size_t) max(16 * 1024, PTHREAD_STACK_MIN));
	BUG_ON(err);
	err = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(err);
	err = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(err);
	for (i = 0; i < sched->nr_tasks; i++) {
		struct sched_thread_parms *parms = malloc(sizeof(*parms));
		BUG_ON(parms == NULL);
		parms->task = task = sched->tasks[i];
		parms->sched = sched;
		sem_init(&task->sleep_sem, 0, 0);
		sem_init(&task->ready_for_work, 0, 0);
		sem_init(&task->work_done_sem, 0, 0);
		task->curr_event = 0;
		err = pthread_create(&task->thread, &attr, thread_func, parms);
		BUG_ON(err);
	}
}

static void wait_for_tasks(struct perf_sched *sched)
{
	u64 cpu_usage_0, cpu_usage_1;
	struct task_desc *task;
	unsigned long i, ret;

	sched->start_time = get_nsecs();
	sched->cpu_usage = 0;
	pthread_mutex_unlock(&sched->work_done_wait_mutex);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		ret = sem_wait(&task->ready_for_work);
		BUG_ON(ret);
		sem_init(&task->ready_for_work, 0, 0);
	}
	ret = pthread_mutex_lock(&sched->work_done_wait_mutex);
	BUG_ON(ret);

	cpu_usage_0 = get_cpu_usage_nsec_parent();

	pthread_mutex_unlock(&sched->start_work_mutex);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		ret = sem_wait(&task->work_done_sem);
		BUG_ON(ret);
		sem_init(&task->work_done_sem, 0, 0);
		sched->cpu_usage += task->cpu_usage;
		task->cpu_usage = 0;
	}

	cpu_usage_1 = get_cpu_usage_nsec_parent();
	if (!sched->runavg_cpu_usage)
		sched->runavg_cpu_usage = sched->cpu_usage;
	sched->runavg_cpu_usage = (sched->runavg_cpu_usage * 9 + sched->cpu_usage) / 10;

	sched->parent_cpu_usage = cpu_usage_1 - cpu_usage_0;
	if (!sched->runavg_parent_cpu_usage)
		sched->runavg_parent_cpu_usage = sched->parent_cpu_usage;
	sched->runavg_parent_cpu_usage = (sched->runavg_parent_cpu_usage * 9 +
					 sched->parent_cpu_usage)/10;

	ret = pthread_mutex_lock(&sched->start_work_mutex);
	BUG_ON(ret);

	for (i = 0; i < sched->nr_tasks; i++) {
		task = sched->tasks[i];
		sem_init(&task->sleep_sem, 0, 0);
		task->curr_event = 0;
	}
}

static void run_one_test(struct perf_sched *sched)
{
	u64 T0, T1, delta, avg_delta, fluct;

	T0 = get_nsecs();
	wait_for_tasks(sched);
	T1 = get_nsecs();

	delta = T1 - T0;
	sched->sum_runtime += delta;
	sched->nr_runs++;

	avg_delta = sched->sum_runtime / sched->nr_runs;
	if (delta < avg_delta)
		fluct = avg_delta - delta;
	else
		fluct = delta - avg_delta;
	sched->sum_fluct += fluct;
	if (!sched->run_avg)
		sched->run_avg = delta;
	sched->run_avg = (sched->run_avg * 9 + delta) / 10;

	printf("#%-3ld: %0.3f, ", sched->nr_runs, (double)delta / 1000000.0);

	printf("ravg: %0.2f, ", (double)sched->run_avg / 1e6);

	printf("cpu: %0.2f / %0.2f",
		(double)sched->cpu_usage / 1e6, (double)sched->runavg_cpu_usage / 1e6);

#if 0
	/*
	 * rusage statistics done by the parent, these are less
	 * accurate than the sched->sum_exec_runtime based statistics:
	 */
	printf(" [%0.2f / %0.2f]",
		(double)sched->parent_cpu_usage/1e6,
		(double)sched->runavg_parent_cpu_usage/1e6);
#endif

	printf("\n");

	if (sched->nr_sleep_corrections)
		printf(" (%ld sleep corrections)\n", sched->nr_sleep_corrections);
	sched->nr_sleep_corrections = 0;
}

static void test_calibrations(struct perf_sched *sched)
{
	u64 T0, T1;

	T0 = get_nsecs();
	burn_nsecs(sched, 1e6);
	T1 = get_nsecs();

	printf("the run test took %" PRIu64 " nsecs\n", T1 - T0);

	T0 = get_nsecs();
	sleep_nsecs(1e6);
	T1 = get_nsecs();

	printf("the sleep test took %" PRIu64 " nsecs\n", T1 - T0);
}

static int
replay_wakeup_event(struct perf_sched *sched,
		    struct perf_evsel *evsel, struct perf_sample *sample,
		    struct machine *machine __maybe_unused)
{
	const char *comm = perf_evsel__strval(evsel, sample, "comm");
	const u32 pid	 = perf_evsel__intval(evsel, sample, "pid");
	struct task_desc *waker, *wakee;

	if (verbose) {
		printf("sched_wakeup event %p\n", evsel);

		printf(" ... pid %d woke up %s/%d\n", sample->tid, comm, pid);
	}

	waker = register_pid(sched, sample->tid, "<unknown>");
	wakee = register_pid(sched, pid, comm);

	add_sched_event_wakeup(sched, waker, sample->time, wakee);
	return 0;
}

static int replay_switch_event(struct perf_sched *sched,
			       struct perf_evsel *evsel,
			       struct perf_sample *sample,
			       struct machine *machine __maybe_unused)
{
	const char *prev_comm  = perf_evsel__strval(evsel, sample, "prev_comm"),
		   *next_comm  = perf_evsel__strval(evsel, sample, "next_comm");
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	const u64 prev_state = perf_evsel__intval(evsel, sample, "prev_state");
	struct task_desc *prev, __maybe_unused *next;
	u64 timestamp0, timestamp = sample->time;
	int cpu = sample->cpu;
	s64 delta;

	if (verbose)
		printf("sched_switch event %p\n", evsel);

	if (cpu >= MAX_CPUS || cpu < 0)
		return 0;

	timestamp0 = sched->cpu_last_switched[cpu];
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	pr_debug(" ... switch from %s/%d to %s/%d [ran %" PRIu64 " nsecs]\n",
		 prev_comm, prev_pid, next_comm, next_pid, delta);

	prev = register_pid(sched, prev_pid, prev_comm);
	next = register_pid(sched, next_pid, next_comm);

	sched->cpu_last_switched[cpu] = timestamp;

	add_sched_event_run(sched, prev, timestamp, delta);
	add_sched_event_sleep(sched, prev, timestamp, prev_state);

	return 0;
}

static int replay_fork_event(struct perf_sched *sched,
			     union perf_event *event,
			     struct machine *machine)
{
	struct thread *child, *parent;

	child = machine__findnew_thread(machine, event->fork.pid,
					event->fork.tid);
	parent = machine__findnew_thread(machine, event->fork.ppid,
					 event->fork.ptid);

	if (child == NULL || parent == NULL) {
		pr_debug("thread does not exist on fork event: child %p, parent %p\n",
				 child, parent);
		return 0;
	}

	if (verbose) {
		printf("fork event\n");
		printf("... parent: %s/%d\n", thread__comm_str(parent), parent->tid);
		printf("...  child: %s/%d\n", thread__comm_str(child), child->tid);
	}

	register_pid(sched, parent->tid, thread__comm_str(parent));
	register_pid(sched, child->tid, thread__comm_str(child));
	return 0;
}

struct sort_dimension {
	const char		*name;
	sort_fn_t		cmp;
	struct list_head	list;
};

static int
thread_lat_cmp(struct list_head *list, struct work_atoms *l, struct work_atoms *r)
{
	struct sort_dimension *sort;
	int ret = 0;

	BUG_ON(list_empty(list));

	list_for_each_entry(sort, list, list) {
		ret = sort->cmp(l, r);
		if (ret)
			return ret;
	}

	return ret;
}

static struct work_atoms *
thread_atoms_search(struct rb_root *root, struct thread *thread,
			 struct list_head *sort_list)
{
	struct rb_node *node = root->rb_node;
	struct work_atoms key = { .thread = thread };

	while (node) {
		struct work_atoms *atoms;
		int cmp;

		atoms = container_of(node, struct work_atoms, node);

		cmp = thread_lat_cmp(sort_list, &key, atoms);
		if (cmp > 0)
			node = node->rb_left;
		else if (cmp < 0)
			node = node->rb_right;
		else {
			BUG_ON(thread != atoms->thread);
			return atoms;
		}
	}
	return NULL;
}

static void
__thread_latency_insert(struct rb_root *root, struct work_atoms *data,
			 struct list_head *sort_list)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct work_atoms *this;
		int cmp;

		this = container_of(*new, struct work_atoms, node);
		parent = *new;

		cmp = thread_lat_cmp(sort_list, data, this);

		if (cmp > 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static int thread_atoms_insert(struct perf_sched *sched, struct thread *thread)
{
	struct work_atoms *atoms = zalloc(sizeof(*atoms));
	if (!atoms) {
		pr_err("No memory at %s\n", __func__);
		return -1;
	}

	atoms->thread = thread;
	INIT_LIST_HEAD(&atoms->work_list);
	__thread_latency_insert(&sched->atom_root, atoms, &sched->cmp_pid);
	return 0;
}

static char sched_out_state(u64 prev_state)
{
	const char *str = TASK_STATE_TO_CHAR_STR;

	return str[prev_state];
}

static int
add_sched_out_event(struct work_atoms *atoms,
		    char run_state,
		    u64 timestamp)
{
	struct work_atom *atom = zalloc(sizeof(*atom));
	if (!atom) {
		pr_err("Non memory at %s", __func__);
		return -1;
	}

	atom->sched_out_time = timestamp;

	if (run_state == 'R') {
		atom->state = THREAD_WAIT_CPU;
		atom->wake_up_time = atom->sched_out_time;
	}

	list_add_tail(&atom->list, &atoms->work_list);
	return 0;
}

static void
add_runtime_event(struct work_atoms *atoms, u64 delta,
		  u64 timestamp __maybe_unused)
{
	struct work_atom *atom;

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	atom->runtime += delta;
	atoms->total_runtime += delta;
}

static void
add_sched_in_event(struct work_atoms *atoms, u64 timestamp)
{
	struct work_atom *atom;
	u64 delta;

	if (list_empty(&atoms->work_list))
		return;

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	if (atom->state != THREAD_WAIT_CPU)
		return;

	if (timestamp < atom->wake_up_time) {
		atom->state = THREAD_IGNORE;
		return;
	}

	atom->state = THREAD_SCHED_IN;
	atom->sched_in_time = timestamp;

	delta = atom->sched_in_time - atom->wake_up_time;
	atoms->total_lat += delta;
	if (delta > atoms->max_lat) {
		atoms->max_lat = delta;
		atoms->max_lat_at = timestamp;
	}
	atoms->nb_atoms++;
}

static int latency_switch_event(struct perf_sched *sched,
				struct perf_evsel *evsel,
				struct perf_sample *sample,
				struct machine *machine)
{
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	const u64 prev_state = perf_evsel__intval(evsel, sample, "prev_state");
	struct work_atoms *out_events, *in_events;
	struct thread *sched_out, *sched_in;
	u64 timestamp0, timestamp = sample->time;
	int cpu = sample->cpu;
	s64 delta;

	BUG_ON(cpu >= MAX_CPUS || cpu < 0);

	timestamp0 = sched->cpu_last_switched[cpu];
	sched->cpu_last_switched[cpu] = timestamp;
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	sched_out = machine__findnew_thread(machine, 0, prev_pid);
	sched_in = machine__findnew_thread(machine, 0, next_pid);

	out_events = thread_atoms_search(&sched->atom_root, sched_out, &sched->cmp_pid);
	if (!out_events) {
		if (thread_atoms_insert(sched, sched_out))
			return -1;
		out_events = thread_atoms_search(&sched->atom_root, sched_out, &sched->cmp_pid);
		if (!out_events) {
			pr_err("out-event: Internal tree error");
			return -1;
		}
	}
	if (add_sched_out_event(out_events, sched_out_state(prev_state), timestamp))
		return -1;

	in_events = thread_atoms_search(&sched->atom_root, sched_in, &sched->cmp_pid);
	if (!in_events) {
		if (thread_atoms_insert(sched, sched_in))
			return -1;
		in_events = thread_atoms_search(&sched->atom_root, sched_in, &sched->cmp_pid);
		if (!in_events) {
			pr_err("in-event: Internal tree error");
			return -1;
		}
		/*
		 * Take came in we have not heard about yet,
		 * add in an initial atom in runnable state:
		 */
		if (add_sched_out_event(in_events, 'R', timestamp))
			return -1;
	}
	add_sched_in_event(in_events, timestamp);

	return 0;
}

static int latency_runtime_event(struct perf_sched *sched,
				 struct perf_evsel *evsel,
				 struct perf_sample *sample,
				 struct machine *machine)
{
	const u32 pid	   = perf_evsel__intval(evsel, sample, "pid");
	const u64 runtime  = perf_evsel__intval(evsel, sample, "runtime");
	struct thread *thread = machine__findnew_thread(machine, 0, pid);
	struct work_atoms *atoms = thread_atoms_search(&sched->atom_root, thread, &sched->cmp_pid);
	u64 timestamp = sample->time;
	int cpu = sample->cpu;

	BUG_ON(cpu >= MAX_CPUS || cpu < 0);
	if (!atoms) {
		if (thread_atoms_insert(sched, thread))
			return -1;
		atoms = thread_atoms_search(&sched->atom_root, thread, &sched->cmp_pid);
		if (!atoms) {
			pr_err("in-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'R', timestamp))
			return -1;
	}

	add_runtime_event(atoms, runtime, timestamp);
	return 0;
}

static int latency_wakeup_event(struct perf_sched *sched,
				struct perf_evsel *evsel,
				struct perf_sample *sample,
				struct machine *machine)
{
	const u32 pid	  = perf_evsel__intval(evsel, sample, "pid"),
		  success = perf_evsel__intval(evsel, sample, "success");
	struct work_atoms *atoms;
	struct work_atom *atom;
	struct thread *wakee;
	u64 timestamp = sample->time;

	/* Note for later, it may be interesting to observe the failing cases */
	if (!success)
		return 0;

	wakee = machine__findnew_thread(machine, 0, pid);
	atoms = thread_atoms_search(&sched->atom_root, wakee, &sched->cmp_pid);
	if (!atoms) {
		if (thread_atoms_insert(sched, wakee))
			return -1;
		atoms = thread_atoms_search(&sched->atom_root, wakee, &sched->cmp_pid);
		if (!atoms) {
			pr_err("wakeup-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'S', timestamp))
			return -1;
	}

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);

	/*
	 * You WILL be missing events if you've recorded only
	 * one CPU, or are only looking at only one, so don't
	 * make useless noise.
	 */
	if (sched->profile_cpu == -1 && atom->state != THREAD_SLEEPING)
		sched->nr_state_machine_bugs++;

	sched->nr_timestamps++;
	if (atom->sched_out_time > timestamp) {
		sched->nr_unordered_timestamps++;
		return 0;
	}

	atom->state = THREAD_WAIT_CPU;
	atom->wake_up_time = timestamp;
	return 0;
}

static int latency_migrate_task_event(struct perf_sched *sched,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	const u32 pid = perf_evsel__intval(evsel, sample, "pid");
	u64 timestamp = sample->time;
	struct work_atoms *atoms;
	struct work_atom *atom;
	struct thread *migrant;

	/*
	 * Only need to worry about migration when profiling one CPU.
	 */
	if (sched->profile_cpu == -1)
		return 0;

	migrant = machine__findnew_thread(machine, 0, pid);
	atoms = thread_atoms_search(&sched->atom_root, migrant, &sched->cmp_pid);
	if (!atoms) {
		if (thread_atoms_insert(sched, migrant))
			return -1;
		register_pid(sched, migrant->tid, thread__comm_str(migrant));
		atoms = thread_atoms_search(&sched->atom_root, migrant, &sched->cmp_pid);
		if (!atoms) {
			pr_err("migration-event: Internal tree error");
			return -1;
		}
		if (add_sched_out_event(atoms, 'R', timestamp))
			return -1;
	}

	BUG_ON(list_empty(&atoms->work_list));

	atom = list_entry(atoms->work_list.prev, struct work_atom, list);
	atom->sched_in_time = atom->sched_out_time = atom->wake_up_time = timestamp;

	sched->nr_timestamps++;

	if (atom->sched_out_time > timestamp)
		sched->nr_unordered_timestamps++;

	return 0;
}

static void output_lat_thread(struct perf_sched *sched, struct work_atoms *work_list)
{
	int i;
	int ret;
	u64 avg;

	if (!work_list->nb_atoms)
		return;
	/*
	 * Ignore idle threads:
	 */
	if (!strcmp(thread__comm_str(work_list->thread), "swapper"))
		return;

	sched->all_runtime += work_list->total_runtime;
	sched->all_count   += work_list->nb_atoms;

	ret = printf("  %s:%d ", thread__comm_str(work_list->thread), work_list->thread->tid);

	for (i = 0; i < 24 - ret; i++)
		printf(" ");

	avg = work_list->total_lat / work_list->nb_atoms;

	printf("|%11.3f ms |%9" PRIu64 " | avg:%9.3f ms | max:%9.3f ms | max at: %9.6f s\n",
	      (double)work_list->total_runtime / 1e6,
		 work_list->nb_atoms, (double)avg / 1e6,
		 (double)work_list->max_lat / 1e6,
		 (double)work_list->max_lat_at / 1e9);
}

static int pid_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->thread->tid < r->thread->tid)
		return -1;
	if (l->thread->tid > r->thread->tid)
		return 1;

	return 0;
}

static int avg_cmp(struct work_atoms *l, struct work_atoms *r)
{
	u64 avgl, avgr;

	if (!l->nb_atoms)
		return -1;

	if (!r->nb_atoms)
		return 1;

	avgl = l->total_lat / l->nb_atoms;
	avgr = r->total_lat / r->nb_atoms;

	if (avgl < avgr)
		return -1;
	if (avgl > avgr)
		return 1;

	return 0;
}

static int max_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->max_lat < r->max_lat)
		return -1;
	if (l->max_lat > r->max_lat)
		return 1;

	return 0;
}

static int switch_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->nb_atoms < r->nb_atoms)
		return -1;
	if (l->nb_atoms > r->nb_atoms)
		return 1;

	return 0;
}

static int runtime_cmp(struct work_atoms *l, struct work_atoms *r)
{
	if (l->total_runtime < r->total_runtime)
		return -1;
	if (l->total_runtime > r->total_runtime)
		return 1;

	return 0;
}

static int sort_dimension__add(const char *tok, struct list_head *list)
{
	size_t i;
	static struct sort_dimension avg_sort_dimension = {
		.name = "avg",
		.cmp  = avg_cmp,
	};
	static struct sort_dimension max_sort_dimension = {
		.name = "max",
		.cmp  = max_cmp,
	};
	static struct sort_dimension pid_sort_dimension = {
		.name = "pid",
		.cmp  = pid_cmp,
	};
	static struct sort_dimension runtime_sort_dimension = {
		.name = "runtime",
		.cmp  = runtime_cmp,
	};
	static struct sort_dimension switch_sort_dimension = {
		.name = "switch",
		.cmp  = switch_cmp,
	};
	struct sort_dimension *available_sorts[] = {
		&pid_sort_dimension,
		&avg_sort_dimension,
		&max_sort_dimension,
		&switch_sort_dimension,
		&runtime_sort_dimension,
	};

	for (i = 0; i < ARRAY_SIZE(available_sorts); i++) {
		if (!strcmp(available_sorts[i]->name, tok)) {
			list_add_tail(&available_sorts[i]->list, list);

			return 0;
		}
	}

	return -1;
}

static void perf_sched__sort_lat(struct perf_sched *sched)
{
	struct rb_node *node;

	for (;;) {
		struct work_atoms *data;
		node = rb_first(&sched->atom_root);
		if (!node)
			break;

		rb_erase(node, &sched->atom_root);
		data = rb_entry(node, struct work_atoms, node);
		__thread_latency_insert(&sched->sorted_atom_root, data, &sched->sort_list);
	}
}

static int process_sched_wakeup_event(struct perf_tool *tool,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->wakeup_event)
		return sched->tp_handler->wakeup_event(sched, evsel, sample, machine);

	return 0;
}

static int map_switch_event(struct perf_sched *sched, struct perf_evsel *evsel,
			    struct perf_sample *sample, struct machine *machine)
{
	const u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
		  next_pid = perf_evsel__intval(evsel, sample, "next_pid");
	struct thread *sched_out __maybe_unused, *sched_in;
	int new_shortname;
	u64 timestamp0, timestamp = sample->time;
	s64 delta;
	int cpu, this_cpu = sample->cpu;

	BUG_ON(this_cpu >= MAX_CPUS || this_cpu < 0);

	if (this_cpu > sched->max_cpu)
		sched->max_cpu = this_cpu;

	timestamp0 = sched->cpu_last_switched[this_cpu];
	sched->cpu_last_switched[this_cpu] = timestamp;
	if (timestamp0)
		delta = timestamp - timestamp0;
	else
		delta = 0;

	if (delta < 0) {
		pr_err("hm, delta: %" PRIu64 " < 0 ?\n", delta);
		return -1;
	}

	sched_out = machine__findnew_thread(machine, 0, prev_pid);
	sched_in = machine__findnew_thread(machine, 0, next_pid);

	sched->curr_thread[this_cpu] = sched_in;

	printf("  ");

	new_shortname = 0;
	if (!sched_in->shortname[0]) {
		sched_in->shortname[0] = sched->next_shortname1;
		sched_in->shortname[1] = sched->next_shortname2;

		if (sched->next_shortname1 < 'Z') {
			sched->next_shortname1++;
		} else {
			sched->next_shortname1='A';
			if (sched->next_shortname2 < '9') {
				sched->next_shortname2++;
			} else {
				sched->next_shortname2='0';
			}
		}
		new_shortname = 1;
	}

	for (cpu = 0; cpu <= sched->max_cpu; cpu++) {
		if (cpu != this_cpu)
			printf(" ");
		else
			printf("*");

		if (sched->curr_thread[cpu]) {
			if (sched->curr_thread[cpu]->tid)
				printf("%2s ", sched->curr_thread[cpu]->shortname);
			else
				printf(".  ");
		} else
			printf("   ");
	}

	printf("  %12.6f secs ", (double)timestamp/1e9);
	if (new_shortname) {
		printf("%s => %s:%d\n",
		       sched_in->shortname, thread__comm_str(sched_in), sched_in->tid);
	} else {
		printf("\n");
	}

	return 0;
}

static int process_sched_switch_event(struct perf_tool *tool,
				      struct perf_evsel *evsel,
				      struct perf_sample *sample,
				      struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	int this_cpu = sample->cpu, err = 0;
	u32 prev_pid = perf_evsel__intval(evsel, sample, "prev_pid"),
	    next_pid = perf_evsel__intval(evsel, sample, "next_pid");

	if (sched->curr_pid[this_cpu] != (u32)-1) {
		/*
		 * Are we trying to switch away a PID that is
		 * not current?
		 */
		if (sched->curr_pid[this_cpu] != prev_pid)
			sched->nr_context_switch_bugs++;
	}

	if (sched->tp_handler->switch_event)
		err = sched->tp_handler->switch_event(sched, evsel, sample, machine);

	sched->curr_pid[this_cpu] = next_pid;
	return err;
}

static int process_sched_runtime_event(struct perf_tool *tool,
				       struct perf_evsel *evsel,
				       struct perf_sample *sample,
				       struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->runtime_event)
		return sched->tp_handler->runtime_event(sched, evsel, sample, machine);

	return 0;
}

static int perf_sched__process_fork_event(struct perf_tool *tool,
					  union perf_event *event,
					  struct perf_sample *sample,
					  struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	/* run the fork event through the perf machineruy */
	perf_event__process_fork(tool, event, sample, machine);

	/* and then run additional processing needed for this command */
	if (sched->tp_handler->fork_event)
		return sched->tp_handler->fork_event(sched, event, machine);

	return 0;
}

static int process_sched_migrate_task_event(struct perf_tool *tool,
					    struct perf_evsel *evsel,
					    struct perf_sample *sample,
					    struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);

	if (sched->tp_handler->migrate_task_event)
		return sched->tp_handler->migrate_task_event(sched, evsel, sample, machine);

	return 0;
}

typedef int (*tracepoint_handler)(struct perf_tool *tool,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct machine *machine);

static int perf_sched__process_tracepoint_sample(struct perf_tool *tool __maybe_unused,
						 union perf_event *event __maybe_unused,
						 struct perf_sample *sample,
						 struct perf_evsel *evsel,
						 struct machine *machine)
{
	int err = 0;

	evsel->hists.stats.total_period += sample->period;
	hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);

	if (evsel->handler != NULL) {
		tracepoint_handler f = evsel->handler;
		err = f(tool, evsel, sample, machine);
	}

	return err;
}

static int perf_sched__read_events(struct perf_sched *sched,
				   struct perf_session **psession)
{
	const struct perf_evsel_str_handler handlers[] = {
		{ "sched:sched_switch",	      process_sched_switch_event, },
		{ "sched:sched_stat_runtime", process_sched_runtime_event, },
		{ "sched:sched_wakeup",	      process_sched_wakeup_event, },
		{ "sched:sched_wakeup_new",   process_sched_wakeup_event, },
		{ "sched:sched_migrate_task", process_sched_migrate_task_event, },
	};
	struct perf_session *session;
	struct perf_data_file file = {
		.path = input_name,
		.mode = PERF_DATA_MODE_READ,
	};

	session = perf_session__new(&file, false, &sched->tool);
	if (session == NULL) {
		pr_debug("No Memory for session\n");
		return -1;
	}

	if (perf_session__set_tracepoints_handlers(session, handlers))
		goto out_delete;

	if (perf_session__has_traces(session, "record -R")) {
		int err = perf_session__process_events(session, &sched->tool);
		if (err) {
			pr_err("Failed to process events, error %d", err);
			goto out_delete;
		}

		sched->nr_events      = session->stats.nr_events[0];
		sched->nr_lost_events = session->stats.total_lost;
		sched->nr_lost_chunks = session->stats.nr_events[PERF_RECORD_LOST];
	}

	if (psession)
		*psession = session;
	else
		perf_session__delete(session);

	return 0;

out_delete:
	perf_session__delete(session);
	return -1;
}

static inline void printf_nsecs(FILE *fp, unsigned long long nsecs, int width_sec)
{
	unsigned long msecs;
	unsigned long usecs;

	msecs = nsecs / NSEC_PER_MSEC;
	nsecs -= msecs * NSEC_PER_MSEC;
	usecs = nsecs / NSEC_PER_USEC;
	fprintf(fp, "%*lu.%03lu ", width_sec, msecs, usecs);
}

static struct evsel_runtime *perf_evsel__get_runtime(struct perf_evsel *evsel)
{
	struct evsel_runtime *r = evsel->priv;

	if (r == NULL) {
		r = zalloc(sizeof(struct evsel_runtime));
		evsel->priv = r;
	}

	return r;
}

static void perf_evsel__save_time(struct perf_evsel *evsel,
				  u64 timestamp, u32 cpu)
{
	struct evsel_runtime *r = perf_evsel__get_runtime(evsel);

	if (r == NULL)
		return;

	if ((cpu > r->ncpu) || (r->last_time == NULL)) {
		unsigned int i;
		void *p = r->last_time;

		r->last_time = realloc(r->last_time, (cpu+1) * sizeof(u64));
		if (!r->last_time) {
			free(p);
			return;
		}

		i = r->ncpu ? r->ncpu + 1 : 0;
		for (; i <= cpu; ++i)
			r->last_time[i] = (u64) 0;

		r->ncpu = cpu;
	}

	r->last_time[cpu] = timestamp;
}

static u64 perf_evsel__get_time(struct perf_evsel *evsel, u32 cpu)
{
	struct evsel_runtime *r = perf_evsel__get_runtime(evsel);

	if ((r == NULL) || (r->last_time == NULL) || (cpu > r->ncpu))
		return 0;

	return r->last_time[cpu];
}

static int comm_width = 20;

static char *timehist_get_commstr(struct thread *thread)
{
	static char str[32];
	const char *comm = thread__comm_str(thread);
	pid_t tid = thread->tid;
	pid_t pid = thread->pid_;
	int n;

	if (pid == 0)
		n = scnprintf(str, sizeof(str), "%s", comm);

	else if (tid != pid)
		n = scnprintf(str, sizeof(str), "%s[%d/%d]", comm, tid, pid);

	else
		n = scnprintf(str, sizeof(str), "%s[%d]", comm, tid);

	if (n > comm_width)
		comm_width = n;

	return str;
}

static void timehist_header(struct perf_sched *sched)
{
	FILE *fp = sched->fp;
	u32 max_cpus = sched->max_cpu;
	u32 i, j;

	fprintf(fp, "%15s %4s ", "time", "cpu");

	if (sched->show_cpu_visual && max_cpus) {
		fprintf(fp, "  ");
		for (i = 0, j = 0; i < max_cpus; ++i) {
			fprintf(fp, "%x", j++);
			if (j > 15)
				j = 0;
		}
		fprintf(fp, " ");
	}

	fprintf(fp, " %-20s  %9s  %9s  %9s",
		"task name", "b/n time", "sch delay", "run time");

	if (sched->show_wakeups)
		fprintf(fp, "  %-20s", "wakeup");

	fprintf(fp, "\n");

	/*
	 * units row
	 */
	fprintf(fp, "%15s %-4s ", "", "");
	if (sched->show_cpu_visual && max_cpus)
		fprintf(fp, " %*s  ", max_cpus, "");
	fprintf(fp, " %-20s  %9s  %9s  %9s\n", "[tid/pid]", "(msec)", "(msec)", "(msec)");

	/*
	 * separator
	 */
	fprintf(fp, "%.15s %.4s ", graph_dotted_line, graph_dotted_line);

	if (sched->show_cpu_visual && max_cpus)
		fprintf(fp, " %.*s  ", max_cpus+1, graph_dotted_line);

	fprintf(fp, " %.20s  %.9s  %.9s  %.9s",
		graph_dotted_line, graph_dotted_line, graph_dotted_line,
		graph_dotted_line);

	if (sched->show_wakeups)
		fprintf(fp, "  %.20s", graph_dotted_line);

	fprintf(fp, "\n");
}

static void timehist_print_sample(struct perf_sched *sched,
				  union perf_event *event,
				  struct perf_evsel *evsel,
				  struct perf_sample *sample,
				  struct thread *thread,
				  struct machine *machine,
				  u64 t, bool start_only)
{
	struct thread_runtime *tr = thread__priv(thread);
	char tstr[64];
	u32 max_cpus = sched->max_cpu;
	FILE *fp = sched->fp;

	fprintf(fp, "%15s ", perf_time__str(tstr, sizeof(tstr), t, NULL));

	fprintf(fp, "[%02d] ", sample->cpu);

	if (sched->show_cpu_visual && max_cpus) {
		u32 i;
		char c;

		fprintf(fp, "  ");
		for (i = 0; i < max_cpus; ++i) {
			/* flag idle times with 'i'; others are sched events */
			if (i == sample->cpu)
				c = (thread->tid == 0) ? 'i' : 's';
			else
				c = ' ';
			fprintf(fp, "%c", c);
		}
		fprintf(fp, "  ");
	}

	fprintf(fp, " %-*s ", comm_width, timehist_get_commstr(thread));

	if (start_only)
		return;

	printf_nsecs(fp, tr->dt_between, 6);
	printf_nsecs(fp, tr->dt_delay, 6);
	printf_nsecs(fp, tr->dt_run, 6);

	if (sched->show_wakeups)
		fprintf(fp, "  %-*s", comm_width, "");

	if (thread->tid == 0)
		goto out;

	if (sched->show_callchain) {
		fprintf(fp, "  ");

		perf_evsel__print_ip(fp, evsel, event, sample, machine,
				     PRINT_IP_OPT_SYM | PRINT_IP_OPT_ONELINE,
				     sched->max_stack, PERF_MAX_STACK_DEPTH,
				     PERF_MAX_STACK_DEPTH);
	}
out:
	fprintf(fp, "\n");
}

/*
 * Explanation of delta-time stats:
 *
 *            t = time of current schedule out event
 *        tprev = time of previous sched out event
 *                also time of schedule-in event for current task
 *    last_time = time of last sched change event for current task
 *                (i.e, time process was last scheduled out)
 * ready_to_run = time of wakeup for current task
 *
 * -----|------------|------------|------------|------
 *    last         ready        tprev          t
 *    time         to run
 *
 *      |------- dt_between ------|
 *                   |- dt_delay -|-- dt_run --|
 *
 *     dt_run = run time of current task
 * dt_between = time between last schedule out event for task and tprev
 *              represents time spent off the cpu
 *   dt_delay = time between wakeup and schedule-in of task
 */

static void timehist_update_runtime_stats(struct thread_runtime *r,
					 u64 t, u64 tprev)
{
	r->dt_delay   = 0;
	r->dt_between = 0;
	r->dt_run     = 0;
	if (tprev) {
		r->dt_run = t - tprev;
		if (r->ready_to_run) {
			if (r->ready_to_run > tprev)
				pr_debug("time travel: wakeup time for task > previous sched_switch event\n");
			else
				r->dt_delay = tprev - r->ready_to_run;
		}

		if (r->last_time > tprev)
			pr_debug("time travel: last sched out time for task > previous sched_switch event\n");
		else if (r->last_time)
			r->dt_between = tprev - r->last_time;
	}

	update_stats(&r->run_stats, r->dt_run);
	r->total_run_time += r->dt_run;
}

static bool is_idle_sample(struct perf_sample *sample,
			   struct perf_evsel *evsel,
			   struct machine *machine)
{
	struct thread *thread;
	struct callchain_cursor *cursor = &callchain_cursor;
	struct callchain_cursor_node *node;
	struct addr_location al;
	int iter = 5;

	/* pid 0 == swapper == idle task */
	if (sample->pid == 0)
		return true;

	if (strcmp(perf_evsel__name(evsel), "sched:sched_switch") == 0) {
		if (perf_evsel__intval(evsel, sample, "prev_pid") == 0)
			return true;
	}

	/* want main thread for process - has maps */
	thread = machine__findnew_thread(machine, sample->pid, sample->pid);
	if (thread == NULL) {
		pr_debug("Failed to get thread for pid %d.\n", sample->pid);
		return false;
	}

	if (!symbol_conf.use_callchain || sample->callchain == NULL)
		return false;

	if (machine__resolve_callchain(machine, evsel, thread,
			      sample, NULL, &al, PERF_MAX_STACK_DEPTH) != 0) {
		if (verbose)
			error("Failed to resolve callchain. Skipping\n");

		return false;
	}
	callchain_cursor_commit(cursor);

	/* idle symbol should be early in the stack */
	while (iter) {
		node = callchain_cursor_current(cursor);
		if (!node)
			break;

		if (symbol__is_idle(node->sym))
			return true;

		callchain_cursor_advance(cursor);

		iter--;
	}

	return false;
}

static int init_idle_threads(int ncpu)
{
	int i;

	if (ncpu == 0)
		ncpu = 16;

	idle_threads = zalloc(ncpu * sizeof(struct thread *));
	if (!idle_threads)
		return -ENOMEM;

	idle_max_cpu = ncpu - 1;

	/* allocate the actual thread struct if needed */
	for (i = 0; i < ncpu; ++i) {
		idle_threads[i] = thread__new(0, 0);
		if (idle_threads[i] == NULL)
			return -ENOMEM;

		thread__set_comm(idle_threads[i], idle_comm, 0);
	}

	return 0;
}

static void free_idle_threads(void)
{
	int i;

	if (idle_threads == NULL)
		return;

	for (i = 0; i <= idle_max_cpu; ++i)
		thread__delete(idle_threads[i]);

	free(idle_threads);
}

static struct thread *get_idle_thread(int cpu)
{
	/*
	 * expand/allocate array of pointers to local thread
	 * structs if needed
	 */
	if ((cpu > idle_max_cpu) || (idle_threads == NULL)) {
		int i, j = 15;
		void *p;

		if (cpu > j)
			j = cpu;

		p = realloc(idle_threads, (j+1) * sizeof(struct thread *));
		if (!p)
			return NULL;

		idle_threads = (struct thread **) p;
		i = idle_max_cpu ? idle_max_cpu + 1 : 0;
		for (; i <= cpu; ++i)
			idle_threads[i] = NULL;

		idle_max_cpu = cpu;
	}

	/* allocate a new thread struct if needed */
	if (idle_threads[cpu] == NULL) {
		idle_threads[cpu] = thread__new(0, 0);
		if (idle_threads[cpu]) {
			idle_threads[cpu]->tid = 0;
			thread__set_comm(idle_threads[cpu], idle_comm, 0);
		}
	}

	return idle_threads[cpu];
}

static struct thread_runtime *thread__init_runtime(struct thread *thread)
{
	struct thread_runtime *r;

	r = zalloc(sizeof(struct thread_runtime));
	if (!r)
		return NULL;

	init_stats(&r->run_stats);
	INIT_LIST_HEAD(&r->children);
	INIT_LIST_HEAD(&r->node);
	r->thread = thread;
	thread__set_priv(thread, r);

	return r;
}

static struct thread_runtime *thread__get_runtime(struct thread *thread)
{
	struct thread_runtime *tr;

	tr = thread__priv(thread);
	if (tr == NULL) {
		tr = thread__init_runtime(thread);
		if (tr == NULL)
			pr_debug("Failed to malloc memory for runtime data.\n");
	}

	return tr;
}

static struct thread *timehist_get_thread(struct perf_sample *sample,
					  struct machine *machine,
					  struct perf_evsel *evsel)
{
	struct thread *thread;

	if (is_idle_sample(sample, evsel, machine)) {
		thread = get_idle_thread(sample->cpu);
		if (thread == NULL)
			pr_err("Failed to get idle thread for cpu %d.\n", sample->cpu);

	} else {
		thread = machine__findnew_thread(machine, sample->pid, sample->tid);
		if (thread == NULL) {
			pr_debug("Failed to get thread for tid %d. skipping sample.\n",
				 sample->tid);
		}
	}

	return thread;
}

static void timehist_add_child(struct thread *t,
			       struct thread *p)
{
	struct thread_runtime *rc, *rp;

	if (p == NULL) {
		pr_err("No parent entry for child %d ppid %d\n",
		       t->tid, t->ppid);
		return;
	}

	rc = thread__get_runtime(t);
	rp = thread__get_runtime(p);

	if (rc == NULL || rp == NULL)
		return;

	if (list_empty(&rc->node)) {
		list_add_tail(&rc->node, &rp->children);
	} else {
		pr_err("thread %s already on a list\n",
		       timehist_get_commstr(rc->thread));
	}
}

/* mark terminated threads in pstree output */
#define TIMEHIST_TERMINATED     " *"

static bool pstree_print_children(FILE *fp, struct thread_runtime *r, int depth)
{
	struct thread_runtime *next;
	bool printed_nl = false;

	depth++;

	if (list_empty(&r->children))
		return false;

	list_for_each_entry(next, &r->children, node) {
		if (next->total_run_time == 0)
			continue;

		printf_nsecs(fp, next->total_run_time, 9);
		fprintf(fp, "msec  ");
		fprintf(fp, "%*s", 8*depth, " ");
		fprintf(fp, "%s", timehist_get_commstr(next->thread));
		fprintf(fp, "%s\n", next->thread->dead ? TIMEHIST_TERMINATED : "");
		printed_nl = pstree_print_children(fp, next, depth);
	}

	if (!printed_nl)
		fprintf(fp, "\n");

	return true;
}

static int pstree_print_thread(struct thread *t, void *priv)
{
	FILE *fp = (FILE *) priv;
	struct thread_runtime *r;

	r = thread__priv(t);
	if (r) {
		/*
		 * only print trees from top parent; skip processes with
		 * 0 runtime if a time window was given
		 */
		if ((t->ppid == -1) && r->total_run_time) {
			printf_nsecs(fp, r->total_run_time, 9);
			fprintf(fp, "msec  ");
			fprintf(fp, "%s", timehist_get_commstr(t));
			fprintf(fp, "%s\n", t->dead ? TIMEHIST_TERMINATED : "");
			if (list_empty(&r->children))
				fprintf(fp, "\n");
			else
				pstree_print_children(fp, r, 0);
		}
	}

	return 0;
}

static int timehist_link_child(struct thread *t, void *priv)
{
	struct thread *p;
	struct machine *m = (struct machine *) priv;

	if (t->ppid > 0) {
		p = machine__find_thread(m, t->ppid);
		timehist_add_child(t, p);
	}

	return 0;
}

static void timehist_pstree(FILE *fp, struct perf_session *session)
{
	struct machine *m = &session->machines.host;

	/* first, link children to parent */
	machine__for_each_thread(m, timehist_link_child, m);

	fprintf(fp, "\n\nParent-child relationships (* = terminated)\n");
	fprintf(fp, "-------------------------------------------\n");

	machine__for_each_thread(m, pstree_print_thread, fp);
}

static bool timehist_skip_sample(struct perf_sched *sched,
				 struct thread *thread)
{
	/*
	 * if user gave a comm list, only show event if waker or wakee
	 * is on the list
	 */
	if (thread__is_filtered(thread))
		return true;

	if (sched->pid && intlist__find(sched->pid, thread->pid_) == NULL)
		return true;

	if (sched->tid && intlist__find(sched->tid, thread->tid) == NULL)
		return true;

	return false;
}

static void timehist_print_wakeup_event(struct perf_sched *sched,
					struct perf_sample *sample,
					struct machine *machine,
					struct thread *awakened)
{
	struct thread *thread;
	char tstr[64];
	FILE *fp = sched->fp;

	thread = machine__findnew_thread(machine, sample->pid, sample->tid);
	if (thread == NULL)
		return;

	/* show wakeup unless both awakee and awaker are filtered */
	if (timehist_skip_sample(sched, thread) &&
	    timehist_skip_sample(sched, awakened)) {
		return;
	}

	fprintf(fp, "%15s ", perf_time__str(tstr, sizeof(tstr), sample->time, NULL));
	fprintf(fp, "[%02d] ", sample->cpu);
	if (sched->show_cpu_visual && sched->max_cpu)
		fprintf(fp, "  %*s  ", sched->max_cpu, "");

	fprintf(fp, " %-*s ", comm_width, timehist_get_commstr(thread));

	/* dt spacer */
	fprintf(fp, "  %9s  %9s  %9s ", "", "", "");

	fprintf(fp, "%-*s", comm_width, timehist_get_commstr(awakened));

	fprintf(fp, "\n");

	return;
}

static int timehist_sched_wakeup_event(struct perf_tool *tool,
				       union perf_event *event __maybe_unused,
				       struct perf_evsel *evsel,
				       struct perf_sample *sample,
				       struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	struct thread *thread;
	struct thread_runtime *tr = NULL;
	/* want pid of awakened task not pid in sample */
	const u32 pid = perf_evsel__intval(evsel, sample, "pid");

	thread = machine__findnew_thread(machine, 0, pid);
	if (thread == NULL)
		return -1;

	tr = thread__get_runtime(thread);
	if (tr == NULL)
		return -1;

	if (tr->ready_to_run == 0)
		tr->ready_to_run = sample->time;

	/* show wakeups if requested */
	if (sched->show_wakeups &&
	    !perf_time__skip_sample(&sched->ptime, sample->time)) {
		timehist_print_wakeup_event(sched, sample, machine, thread);
	}

	return 0;
}

static void timehist_print_migration_event(struct perf_sched *sched,
					struct perf_evsel *evsel,
					struct perf_sample *sample,
					struct machine *machine,
					struct thread *migrated)
{
	struct thread *thread;
	char tstr[64];
	FILE *fp = sched->fp;
	u32 max_cpus = sched->max_cpu;
	u32 ocpu = perf_evsel__intval(evsel, sample, "orig_cpu");
	u32 dcpu = perf_evsel__intval(evsel, sample, "dest_cpu");

	thread = machine__findnew_thread(machine, sample->pid, sample->tid);
	if (thread == NULL)
		return;

	/* show wakeup unless both awakee and awaker are filtered */
	if (timehist_skip_sample(sched, thread) &&
	    timehist_skip_sample(sched, migrated)) {
		return;
	}

	fprintf(fp, "%15s ", perf_time__str(tstr, sizeof(tstr), sample->time, NULL));
	fprintf(fp, "[%02d] ", sample->cpu);

	if (sched->show_cpu_visual && max_cpus) {
		u32 i;
		char c;

		fprintf(fp, "  ");
		for (i = 0; i < max_cpus; ++i) {
			c = (i == sample->cpu) ? 'm' : ' ';
			fprintf(fp, "%c", c);
		}
		fprintf(fp, "  ");
	}

	fprintf(fp, " %-*s ", comm_width, timehist_get_commstr(thread));

	/* dt spacer */
	fprintf(fp, "  %9s  %9s  %9s ", "", "", "");

	fprintf(fp, "%-*s", comm_width, timehist_get_commstr(migrated));
	fprintf(fp, " cpu %d => %d", ocpu, dcpu);

	fprintf(fp, "\n");

	return;
}

static int timehist_migrate_task_event(struct perf_tool *tool,
				       union perf_event *event __maybe_unused,
				       struct perf_evsel *evsel,
				       struct perf_sample *sample,
				       struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	struct thread *thread;
	struct thread_runtime *tr = NULL;
	/* want pid of migrated task not pid in sample */
	const u32 pid = perf_evsel__intval(evsel, sample, "pid");

	thread = machine__findnew_thread(machine, 0, pid);
	if (thread == NULL)
		return -1;

	tr = thread__get_runtime(thread);
	if (tr == NULL)
		return -1;

	tr->migrations++;

	/* show migrations if requested */
	if (sched->show_migrations &&
	    !perf_time__skip_sample(&sched->ptime, sample->time)) {
		timehist_print_migration_event(sched, evsel, sample, machine, thread);
	}

	return 0;
}

static int timehist_sched_change_event(struct perf_tool *tool,
				       union perf_event *event,
				       struct perf_evsel *evsel,
				       struct perf_sample *sample,
				       struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	struct perf_time *ptime = &sched->ptime;
	struct thread *thread;
	struct thread_runtime *tr = NULL;
	u64 tprev, t = sample->time;
	int rc = 0;

	thread = timehist_get_thread(sample, machine, evsel);
	if (thread == NULL) {
		rc = -1;
		goto out;
	}

	if (timehist_skip_sample(sched, thread))
		goto out;

	tr = thread__get_runtime(thread);
	if (tr == NULL) {
		rc = -1;
		goto out;
	}

	tprev = perf_evsel__get_time(evsel, sample->cpu);

	/*
	 * If start time given:
	 * - sample time is under window user cares about - skip sample
	 * - tprev is under window user cares about  - reset to start of window
	 */
	if (ptime->start) {
		if (ptime->start > t)
			goto out;

		if (ptime->start > tprev)
			tprev = ptime->start;
	}

	/*
	 * If end time given:
	 * - previous sched event is out of window - we are done
	 * - sample time is beyond window user cares about - reset it
	 *   to close out stats for time window interest
	 */
	if (ptime->end) {
		if (tprev > ptime->end)
			goto out;

		if (t > ptime->end)
			t = ptime->end;
	}

	timehist_update_runtime_stats(tr, t, tprev);
	if (!sched->summary_only && !sched->pstree_only) {
		timehist_print_sample(sched, event, evsel, sample, thread,
				      machine, t, false);
	}

out:
	if (tr) {
		/* time of this sched_switch event becomes last time task seen */
		tr->last_time = sample->time;

		/* sched out event for task so reset ready to run time */
		tr->ready_to_run = 0;
	}

	perf_evsel__save_time(evsel, sample->time, sample->cpu);

	return rc;
}

static int timehist_cs_event(struct perf_tool *tool __maybe_unused,
			     union perf_event *event,
			     struct perf_evsel *evsel,
			     struct perf_sample *sample,
			     struct machine *machine __maybe_unused)
{
	return timehist_sched_change_event(tool, event, evsel, sample, machine);
}

static int timehist_sched_switch_event(struct perf_tool *tool,
			     union perf_event *event,
			     struct perf_evsel *evsel,
			     struct perf_sample *sample,
			     struct machine *machine __maybe_unused)
{
	return timehist_sched_change_event(tool, event, evsel, sample, machine);
}

#if defined(__i386__) || defined(__x86_64__)
static int timehist_kvm_event(struct perf_tool *tool,
			      union perf_event *event,
			      struct perf_evsel *evsel,
			      struct perf_sample *sample,
			      struct machine *machine,
			      bool entry_event)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	struct thread *thread;
	struct thread_runtime *tr = NULL;
	FILE *fp = sched->fp;
	u64 dt = 0;

	thread = timehist_get_thread(sample, machine, evsel);
	if (thread == NULL)
		return 0;

	tr = thread__get_runtime(thread);
	if (tr == NULL)
		return -1;

	if (entry_event && tr->in_guest && tr->last_time_kvm) {
		pr_debug("double kvm_entry without an exit event\n");
		tr->last_time_kvm = sample->time;
	} else if (!entry_event && !tr->in_guest && tr->last_time_kvm) {
		pr_debug("double kvm_exit without an entry event\n");
		tr->last_time_kvm = sample->time;
	}

	if (!timehist_skip_sample(sched, thread) &&
	    !perf_time__skip_sample(&sched->ptime, sample->time)) {
		timehist_print_sample(sched, event, evsel, sample, thread,
				      machine, sample->time, true);

		fprintf(fp, "%33s", "");

		if (tr->last_time_kvm)
			dt = sample->time - tr->last_time_kvm;

		fprintf(fp, "   ");
		if (entry_event) {
			tr->in_guest = true;

			if (tr->exit_hlt)
				fprintf(fp, "entry");
			else
				fprintf(fp, "entry: %3" PRIu64 " usec out of guest mode", dt/1000);
		} else {
			u64 reason = perf_evsel__intval(evsel, sample, "exit_reason");

			fprintf(fp, " exit: %3" PRIu64 " usec in guest mode", dt/1000);
			fprintf(fp, ", exit: %s", kvm__get_exit_reason(reason));

			tr->exit_hlt = kvm__is_hlt_exit(reason);
			tr->in_guest = false;
		}

		fprintf(fp, "\n");
	}

	tr->last_time_kvm = sample->time;

	return 0;
}

static int timehist_kvm_entry_event(struct perf_tool *tool,
				    union perf_event *event,
				    struct perf_evsel *evsel,
				    struct perf_sample *sample,
				    struct machine *machine)
{
	return timehist_kvm_event(tool, event, evsel, sample, machine, true);
}

static int timehist_kvm_exit_event(struct perf_tool *tool,
				   union perf_event *event,
				   struct perf_evsel *evsel,
				   struct perf_sample *sample,
				   struct machine *machine)
{
	return timehist_kvm_event(tool, event, evsel, sample, machine, false);
}
#endif

static int process_lost(struct perf_tool *tool __maybe_unused,
			union perf_event *event,
			struct perf_sample *sample,
			struct machine *machine __maybe_unused)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	FILE *fp = sched->fp;
	char tstr[64];

	fprintf(fp, "%15s ", perf_time__str(tstr, sizeof(tstr), sample->time, NULL));
	fprintf(fp, "lost %" PRIu64 " events on cpu %d\n", event->lost.lost, sample->cpu);

	return 0;
}


static void print_thread_runtime(FILE *fp, struct thread *t,
				 struct thread_runtime *r)
{
	double mean = avg_stats(&r->run_stats);
	float stddev;

	fprintf(fp, "%*s   %5d  %9" PRIu64 " ",
	       comm_width, timehist_get_commstr(t), t->ppid,
	       (u64) r->run_stats.n);

	printf_nsecs(fp, r->total_run_time, 8);
	stddev = rel_stddev_stats(stddev_stats(&r->run_stats), mean);
	printf_nsecs(fp, r->run_stats.min, 6);
	fprintf(fp, " ");
	printf_nsecs(fp, (u64) mean, 6);
	fprintf(fp, " ");
	printf_nsecs(fp, r->run_stats.max, 6);
	fprintf(fp, "  ");
	fprintf(fp, "%5.2f", stddev);
	fprintf(fp, "   %5" PRIu64, r->migrations);
	fprintf(fp, "\n");
}

struct total_run_stats {
	FILE *fp;
	u64  sched_count;
	u64  task_count;
	u64  total_run_time;
};

static int __show_thread_runtime(struct thread *t, void *priv)
{
	struct total_run_stats *stats = priv;
	struct thread_runtime *r;

	if (thread__is_filtered(t))
		return 0;

	r = thread__priv(t);
	if (r && r->run_stats.n) {
		stats->task_count++;
		stats->sched_count += r->run_stats.n;
		stats->total_run_time += r->total_run_time;
		print_thread_runtime(stats->fp, t, r);
	}

	return 0;
}

static int show_thread_runtime(struct thread *t, void *priv)
{
	if (t->dead)
		return 0;

	return __show_thread_runtime(t, priv);
}

static int show_deadthread_runtime(struct thread *t, void *priv)
{
	if (!t->dead)
		return 0;

	return __show_thread_runtime(t, priv);
}

static void timehist_print_summary(FILE *fp, struct perf_session *session)
{
	struct machine *m = &session->machines.host;
	struct total_run_stats totals;
	struct thread *t;
	struct thread_runtime *r;
	int i;

	memset(&totals, 0, sizeof(totals));

	if (comm_width < 30)
		comm_width = 30;

	fprintf(fp, "\nRuntime summary\n");
	fprintf(fp, "%*s  parent   sched-in  ", comm_width, "comm");
	fprintf(fp, "   run-time    min-run     avg-run     max-run  stddev  migrations\n");
	fprintf(fp, "%*s            (count)  ", comm_width, "");
	fprintf(fp, "     (msec)     (msec)      (msec)      (msec)       %%\n");
	fprintf(fp, "%.117s\n", graph_dotted_line);

	totals.fp = fp;
	machine__for_each_thread(m, show_thread_runtime, &totals);
	fprintf(fp, "\nTerminated tasks:\n");
	machine__for_each_thread(m, show_deadthread_runtime, &totals);

	fprintf(fp, "\nIdle stats:\n");
	for (i = 0; i <= idle_max_cpu; ++i) {
		t = idle_threads[i];
		if (!t)
			continue;

		r = thread__priv(t);
		if (r && r->run_stats.n) {
			totals.sched_count += r->run_stats.n;
			fprintf(fp, "    CPU %2d idle for ", i);
			printf_nsecs(fp, r->total_run_time, 6);
			fprintf(fp, " msec\n");
		} else
			fprintf(fp, "    CPU %2d idle entire time window\n", i);
	}

	fprintf(fp, "\n"
	       "    Total number of unique tasks: %" PRIu64 "\n"
	       "Total number of context switches: %" PRIu64 "\n"
	       "           Total run time (msec): ",
	       totals.task_count, totals.sched_count);

	printf_nsecs(fp, totals.total_run_time, 2);
	fprintf(fp, "\n");
}

typedef int (*sched_handler)(struct perf_tool *tool,
			  union perf_event *event,
			  struct perf_evsel *evsel,
			  struct perf_sample *sample,
			  struct machine *machine);

static int perf_timehist__process_sample(struct perf_tool *tool,
					 union perf_event *event,
					 struct perf_sample *sample,
					 struct perf_evsel *evsel,
					 struct machine *machine)
{
	struct perf_sched *sched = container_of(tool, struct perf_sched, tool);
	int err = 0;
	int this_cpu = sample->cpu;

	if (this_cpu >= sched->max_cpu)
		sched->max_cpu = this_cpu + 1;

	evsel->hists.stats.total_period += sample->period;
	hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);

	if (evsel->handler != NULL) {
		sched_handler f = evsel->handler;

		err = f(tool, event, evsel, sample, machine);
	}

	return err;
}

static int setup_excl_sym(void)
{
	if (excl_sym_list_str &&
	    setup_list(&excl_sym_list, excl_sym_list_str, "excl_sym") < 0)
		return -1;

	return 0;
}

static bool ignore_kernel_stack, ignore_user_stack;

static int timehist_symbol_filter(struct map *map, struct symbol *sym)
{
	if (ignore_kernel_stack && map->dso->kernel != DSO_TYPE_USER) {
		sym->ignore = true;
		return 0;
	}
	if (ignore_user_stack && map->dso->kernel == DSO_TYPE_USER) {
		sym->ignore = true;
		return 0;
	}

	/* filter out schedule and syscall related symbols from stack trace */
	if (map->dso->kernel == DSO_TYPE_KERNEL) {
		if ((strncmp(sym->name, "schedule", 8) == 0) ||
		    (strcmp(sym->name, "__schedule") == 0)) {
			sym->ignore = true;
			return 0;
		}
		if ((strcmp(sym->name, "syscall") == 0) ||
		    (strcmp(sym->name, "system_call_done") == 0) ||
		    (strcmp(sym->name, "ia32_syscall_done") == 0)) {
			sym->ignore = true;
			return 0;
		}
	}

	if ((excl_sym_list && strlist__has_entry(excl_sym_list, sym->name)) ||
	    symbol__is_idle(sym))
		sym->ignore = true;

	return 0;
}

static int parse_target_str(struct perf_sched *sched)
{
	if (sched->target.pid) {
		sched->pid = intlist__new(sched->target.pid);
		if (sched->pid == NULL) {
			pr_err("Error parsing process id string\n");
			return -EINVAL;
		}
	}

	if (sched->target.tid) {
		sched->tid = intlist__new(sched->target.tid);
		if (sched->tid == NULL) {
			intlist__delete(sched->pid);
			pr_err("Error parsing thread id string\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int timehist_check_attr(struct perf_sched *sched,
			       struct perf_evlist *evlist)
{
	struct perf_evsel *evsel, *cs_evsel = NULL;
	struct evsel_runtime *er;
	const char *evname;
	bool have_cs_event = false, have_sched_event = false;

	list_for_each_entry(evsel, &evlist->entries, node) {
		if (evsel->attr.type == PERF_TYPE_TRACEPOINT)
			sched->have_traces = true;

		evname = perf_evsel__name(evsel);
		if (strcmp(evname, "cs") == 0 ||
		    strcmp(evname, "context-switch") == 0) {
			cs_evsel = evsel;
			have_cs_event = true;
		} else if (strcmp(evname, "sched:sched_switch") == 0) {
			have_sched_event = true;
		}


		er = perf_evsel__get_runtime(evsel);
		if (er == NULL) {
			pr_err("Failed to allocate memory for evsel runtime data\n");
			return -1;
		}

		if (sched->show_callchain &&
		    !(evsel->attr.sample_type & PERF_SAMPLE_CALLCHAIN)) {
			pr_info("Samples do not have callchains.\n");
			sched->show_callchain = 0;
			symbol_conf.use_callchain = 0;
		}
	}

	if (have_cs_event && have_sched_event) {
		pr_debug("Both schedule change events exist. Ignoring context-switch event\n");
	} else if (have_cs_event) {
		pr_debug("Using context-switch events.\n");
		cs_evsel->handler = timehist_cs_event;
	}

	return 0;
}

static int perf_sched__timehist(struct perf_sched *sched)
{
	const struct perf_evsel_str_handler handlers[] = {
		{ "sched:sched_switch",       timehist_sched_switch_event, },
		{ "sched:sched_wakeup",	      timehist_sched_wakeup_event, },
		{ "sched:sched_wakeup_new",   timehist_sched_wakeup_event, },
		{ "sched:sched_migrate_task", timehist_migrate_task_event, },
#if defined(__i386__) || defined(__x86_64__)
		{ "kvm:kvm_entry",            timehist_kvm_entry_event, },
		{ "kvm:kvm_exit",             timehist_kvm_exit_event, },
#endif
	};
	struct perf_data_file file = {
		.path = input_name,
		.mode = PERF_DATA_MODE_READ,
	};

	struct perf_session *session;
	int err = -1;

	/*
	 * event handlers for timehist option
	 */
	sched->tool.sample	 = perf_timehist__process_sample;
	sched->tool.mmap	 = perf_event__process_mmap;
	sched->tool.comm	 = perf_event__process_comm;
	sched->tool.exit	 = perf_event__process_exit;
	sched->tool.fork	 = perf_event__process_fork;
	sched->tool.lost	 = process_lost;
	sched->tool.attr	 = perf_event__process_attr;
	sched->tool.tracing_data = perf_event__process_tracing_data;
	sched->tool.build_id	 = perf_event__process_build_id;

	sched->tool.ordered_samples = true;
	sched->tool.ordering_requires_timestamps = true;

	if (setup_excl_sym() < 0)
		return -1;

	symbol_conf.use_callchain = sched->show_callchain;
	if (symbol__init() < 0)
		return -1;

	session = perf_session__new(&file, false, &sched->tool);
	if (session == NULL)
		return -ENOMEM;

	if (perf_time__have_reftime(session) != 0)
		pr_debug("No reference time. Time stamps will be perf_clock\n");

	if (kvm__init(session->header.env.cpuid) < 0)
		goto out;

	/* needs to be parsed after looking up reference time */
	if (perf_time__parse_str(&sched->ptime, sched->time_str, NULL) != 0) {
		pr_err("Invalid time string\n");
		return -EINVAL;
	}

	machines__set_symbol_filter(&session->machines, timehist_symbol_filter);

	if (timehist_check_attr(sched, session->evlist) != 0)
		goto out;

	if (parse_target_str(sched) != 0)
		goto out;

	setup_pager();

	/* setup per-evsel handlers */
	if (sched->have_traces &&
	    perf_session__set_tracepoints_handlers(session, handlers))
		goto out;

	/* pre-allocate struct for per-CPU idle stats */
	sched->max_cpu = session->header.env.nr_cpus_online;
	if (sched->max_cpu == 0)
		sched->max_cpu = 1;  /* have at least 1 cpu */

	if (init_idle_threads(sched->max_cpu))
		goto out;

	/* summary_only implies summary option, but don't overwrite summary if set */
	if (sched->summary_only)
		sched->summary = sched->summary_only;

	if (sched->pstree_only)
		sched->pstree = sched->pstree_only;

	if (!sched->summary_only && !sched->pstree_only)
		timehist_header(sched);

	err = perf_session__process_events(session, &sched->tool);
	if (err) {
		pr_err("Failed to process events, error %d", err);
		goto out;
	}

	sched->nr_events      = session->stats.nr_events[0];
	sched->nr_lost_events = session->stats.total_lost;
	sched->nr_lost_chunks = session->stats.nr_events[PERF_RECORD_LOST];

	if (sched->summary)
		timehist_print_summary(sched->fp, session);

	if (sched->pstree)
		timehist_pstree(sched->fp, session);

out:
	free_idle_threads();
	perf_session__delete(session);

	return err;
}

#include "schedmon.c"

static void print_bad_events(struct perf_sched *sched)
{
	if (sched->nr_unordered_timestamps && sched->nr_timestamps) {
		printf("  INFO: %.3f%% unordered timestamps (%ld out of %ld)\n",
			(double)sched->nr_unordered_timestamps/(double)sched->nr_timestamps*100.0,
			sched->nr_unordered_timestamps, sched->nr_timestamps);
	}
	if (sched->nr_lost_events && sched->nr_events) {
		printf("  INFO: %.3f%% lost events (%ld out of %ld, in %ld chunks)\n",
			(double)sched->nr_lost_events/(double)sched->nr_events * 100.0,
			sched->nr_lost_events, sched->nr_events, sched->nr_lost_chunks);
	}
	if (sched->nr_state_machine_bugs && sched->nr_timestamps) {
		printf("  INFO: %.3f%% state machine bugs (%ld out of %ld)",
			(double)sched->nr_state_machine_bugs/(double)sched->nr_timestamps*100.0,
			sched->nr_state_machine_bugs, sched->nr_timestamps);
		if (sched->nr_lost_events)
			printf(" (due to lost events?)");
		printf("\n");
	}
	if (sched->nr_context_switch_bugs && sched->nr_timestamps) {
		printf("  INFO: %.3f%% context switch bugs (%ld out of %ld)",
			(double)sched->nr_context_switch_bugs/(double)sched->nr_timestamps*100.0,
			sched->nr_context_switch_bugs, sched->nr_timestamps);
		if (sched->nr_lost_events)
			printf(" (due to lost events?)");
		printf("\n");
	}
}

static int perf_sched__lat(struct perf_sched *sched)
{
	struct rb_node *next;
	struct perf_session *session;

	setup_pager();

	/* save session -- references to threads are held in work_list */
	if (perf_sched__read_events(sched, &session))
		return -1;

	perf_sched__sort_lat(sched);

	printf("\n ---------------------------------------------------------------------------------------------------------------\n");
	printf("  Task                  |   Runtime ms  | Switches | Average delay ms | Maximum delay ms | Maximum delay at     |\n");
	printf(" ---------------------------------------------------------------------------------------------------------------\n");

	next = rb_first(&sched->sorted_atom_root);

	while (next) {
		struct work_atoms *work_list;

		work_list = rb_entry(next, struct work_atoms, node);
		output_lat_thread(sched, work_list);
		next = rb_next(next);
	}

	printf(" -----------------------------------------------------------------------------------------\n");
	printf("  TOTAL:                |%11.3f ms |%9" PRIu64 " |\n",
		(double)sched->all_runtime / 1e6, sched->all_count);

	printf(" ---------------------------------------------------\n");

	print_bad_events(sched);
	printf("\n");

	perf_session__delete(session);
	return 0;
}

static int perf_sched__map(struct perf_sched *sched)
{
	sched->max_cpu = sysconf(_SC_NPROCESSORS_CONF);

	setup_pager();
	if (perf_sched__read_events(sched, NULL))
		return -1;
	print_bad_events(sched);
	return 0;
}

static int perf_sched__replay(struct perf_sched *sched)
{
	unsigned long i;

	calibrate_run_measurement_overhead(sched);
	calibrate_sleep_measurement_overhead(sched);

	test_calibrations(sched);

	if (perf_sched__read_events(sched, NULL))
		return -1;

	printf("nr_run_events:        %ld\n", sched->nr_run_events);
	printf("nr_sleep_events:      %ld\n", sched->nr_sleep_events);
	printf("nr_wakeup_events:     %ld\n", sched->nr_wakeup_events);

	if (sched->targetless_wakeups)
		printf("target-less wakeups:  %ld\n", sched->targetless_wakeups);
	if (sched->multitarget_wakeups)
		printf("multi-target wakeups: %ld\n", sched->multitarget_wakeups);
	if (sched->nr_run_events_optimized)
		printf("run atoms optimized: %ld\n",
			sched->nr_run_events_optimized);

	print_task_traces(sched);
	add_cross_task_wakeups(sched);

	create_tasks(sched);
	printf("------------------------------------------------------------\n");
	for (i = 0; i < sched->replay_repeat; i++)
		run_one_test(sched);

	return 0;
}

static void setup_sorting(struct perf_sched *sched, const struct option *options,
			  const char * const usage_msg[])
{
	char *tmp, *tok, *str = strdup(sched->sort_order);

	for (tok = strtok_r(str, ", ", &tmp);
			tok; tok = strtok_r(NULL, ", ", &tmp)) {
		if (sort_dimension__add(tok, &sched->sort_list) < 0) {
			error("Unknown --sort key: `%s'", tok);
			usage_with_options(usage_msg, options);
		}
	}

	free(str);

	sort_dimension__add("pid", &sched->cmp_pid);
}

static int __cmd_record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;
	const char * const record_args[] = {
		"record",
		"-a",
		"-R",
		"-m", "1024",
		"-c", "1",
		"-e", "sched:sched_switch",
		"-e", "sched:sched_stat_wait",
		"-e", "sched:sched_stat_sleep",
		"-e", "sched:sched_stat_iowait",
		"-e", "sched:sched_stat_runtime",
		"-e", "sched:sched_process_fork",
		"-e", "sched:sched_wakeup",
		"-e", "sched:sched_migrate_task",
	};

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	if (rec_argv == NULL)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	return cmd_record(i, rec_argv, NULL);
}

int cmd_sched(int argc, const char **argv, const char *prefix __maybe_unused)
{
	const char default_sort_order[] = "avg, max, switch, runtime";
	struct perf_sched sched = {
		.tool = {
			.sample		 = perf_sched__process_tracepoint_sample,
			.comm		 = perf_event__process_comm,
			.lost		 = perf_event__process_lost,
			.fork		 = perf_sched__process_fork_event,
			.ordered_samples = true,
		},
		.cmp_pid	      = LIST_HEAD_INIT(sched.cmp_pid),
		.sort_list	      = LIST_HEAD_INIT(sched.sort_list),
		.start_work_mutex     = PTHREAD_MUTEX_INITIALIZER,
		.work_done_wait_mutex = PTHREAD_MUTEX_INITIALIZER,
		.sort_order	      = default_sort_order,
		.replay_repeat	      = 10,
		.profile_cpu	      = -1,
		.next_shortname1      = 'A',
		.next_shortname2      = '0',
		.show_callchain	      = 1,
		.max_stack            = 5,
		.fp                   = stdout,
	};
	const struct option latency_options[] = {
	OPT_STRING('s', "sort", &sched.sort_order, "key[,key2...]",
		   "sort by key(s): runtime, switch, avg, max"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_INTEGER('C', "CPU", &sched.profile_cpu,
		    "CPU to profile on"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	const struct option replay_options[] = {
	OPT_UINTEGER('r', "repeat", &sched.replay_repeat,
		     "repeat the workload replay N times (-1: infinite)"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	const struct option sched_options[] = {
	OPT_STRING('i', "input", &input_name, "file",
		    "input file name"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_END()
	};
	bool user_stack_only = false;
	bool kernel_stack_only = false;
	const struct option timehist_options[] = {
	OPT_STRING('i', "input", &input_name, "file",
		    "input file name"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_STRING('k', "vmlinux", &symbol_conf.vmlinux_name,
		   "file", "vmlinux pathname"),
	OPT_STRING(0, "kallsyms", &symbol_conf.kallsyms_name,
		   "file", "kallsyms pathname"),
	OPT_STRING('c', "comms", &symbol_conf.comm_list_str, "comm[,comm...]",
		   "only display events for these comms"),
	OPT_STRING('p', "pid", &sched.target.pid, "pid",
		   "analyze events only for given process id(s)"),
	OPT_STRING('t', "tid", &sched.target.tid, "tid",
		    "analyze events only for given thread id(s)"),
	OPT_BOOLEAN('g', "call-graph", &sched.show_callchain,
		    "Display call chains if present (default on)"),
	OPT_BOOLEAN(0, "ustacks", &user_stack_only, "Only show userspace stacks"),
	OPT_BOOLEAN(0, "kstacks", &kernel_stack_only, "Only show kernel stacks"),
	OPT_UINTEGER(0, "max-stack", &sched.max_stack,
		   "Maximum number of functions to display backtrace."),
	OPT_STRING('x', "exclude-sym", &excl_sym_list_str, "sym[,sym...]",
		   "symbols to skip in backtrace"),
	OPT_STRING(0, "symfs", &symbol_conf.symfs, "directory",
		    "Look for files with symbols relative to this directory"),
	OPT_BOOLEAN('s', "summary", &sched.summary_only,
		    "Show only syscall summary with statistics"),
	OPT_BOOLEAN('S', "with-summary", &sched.summary,
		    "Show all syscalls and summary with statistics"),
	OPT_BOOLEAN('w', "wakeups", &sched.show_wakeups, "Show wakeup events"),
	OPT_BOOLEAN('M', "migrations", &sched.show_migrations, "Show migration events"),
	OPT_BOOLEAN('V', "cpu-visual", &sched.show_cpu_visual, "Add CPU visual"),
	OPT_BOOLEAN('T', "pstree", &sched.pstree_only, "Show only parent-child tree"),
	OPT_BOOLEAN('P', "with-pstree", &sched.pstree, "Show parent-child tree"),
	OPT_STRING(0, "time", &sched.time_str, "str",
		     "Time span for analysis (start,stop)"),
	OPT_END()
	};
	const char * const timehist_usage[] = {
		"perf sched timehist [<options>]",
		NULL
	};

	const char * const latency_usage[] = {
		"perf sched latency [<options>]",
		NULL
	};
	const char * const replay_usage[] = {
		"perf sched replay [<options>]",
		NULL
	};
	const char * const sched_usage[] = {
		"perf sched [<options>] {record|latency|map|replay|script}",
		NULL
	};
	struct trace_sched_handler lat_ops  = {
		.wakeup_event	    = latency_wakeup_event,
		.switch_event	    = latency_switch_event,
		.runtime_event	    = latency_runtime_event,
		.migrate_task_event = latency_migrate_task_event,
	};
	struct trace_sched_handler map_ops  = {
		.switch_event	    = map_switch_event,
	};
	struct trace_sched_handler replay_ops  = {
		.wakeup_event	    = replay_wakeup_event,
		.switch_event	    = replay_switch_event,
		.fork_event	    = replay_fork_event,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sched.curr_pid); i++)
		sched.curr_pid[i] = -1;

	argc = parse_options(argc, argv, sched_options, sched_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(sched_usage, sched_options);

	/*
	 * Aliased to 'perf script' for now:
	 */
	if (!strcmp(argv[0], "script"))
		return cmd_script(argc, argv, prefix);

	if (!strncmp(argv[0], "rec", 3)) {
		return __cmd_record(argc, argv);
	} else if (!strncmp(argv[0], "lat", 3)) {
		sched.tp_handler = &lat_ops;
		if (argc > 1) {
			argc = parse_options(argc, argv, latency_options, latency_usage, 0);
			if (argc)
				usage_with_options(latency_usage, latency_options);
		}
		setup_sorting(&sched, latency_options, latency_usage);
		symbol__init();
		return perf_sched__lat(&sched);
	} else if (!strcmp(argv[0], "map")) {
		sched.tp_handler = &map_ops;
		setup_sorting(&sched, latency_options, latency_usage);
		symbol__init();
		return perf_sched__map(&sched);
	} else if (!strncmp(argv[0], "rep", 3)) {
		sched.tp_handler = &replay_ops;
		if (argc) {
			argc = parse_options(argc, argv, replay_options, replay_usage, 0);
			if (argc)
				usage_with_options(replay_usage, replay_options);
		}
		symbol__init();
		return perf_sched__replay(&sched);
	} else if (!strcmp(argv[0], "timehist")) {
		if (argc) {
			argc = parse_options(argc, argv, timehist_options,
					     timehist_usage, 0);
			if (argc)
				usage_with_options(timehist_usage, timehist_options);
		}
		if (sched.show_wakeups && sched.summary_only) {
			pr_err("-w and -s are mutually exclusive.\n");
			return -EINVAL;
		}
		if (sched.show_migrations && sched.summary_only) {
			pr_err("-M and -s are mutually exclusive.\n");
			return -EINVAL;
		}
		if (user_stack_only && kernel_stack_only) {
			pr_err("--ustack and --kstack are mutually exclusive\n");
			return -EINVAL;
		}
		ignore_kernel_stack = user_stack_only;
		ignore_user_stack   = kernel_stack_only;

		return perf_sched__timehist(&sched);
	} else if (!strcmp(argv[0], "daemon")) {
		return perf_sched__daemon(&sched, argc, argv);
	} else {
		usage_with_options(sched_usage, sched_options);
	}

	return 0;
}
