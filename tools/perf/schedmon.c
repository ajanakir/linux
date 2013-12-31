#include <malloc.h>

/*
 * Defaults to throttle memory consumption.
 *   events: 1M * ~150 bytes/event = 150M
 *     time: 30 seconds
 */
#define MAX_EVENTS  (1024 * 1024)
#define MAX_TIME    30

static u64 time_to_keep;
static unsigned int poll_time = 100;

static const char *output_template = "";
static bool do_compression;

static struct list_head event_list;
static u64 num_events, max_events;
static u64 event_errors;
static u64 timestamp_errors;
static time_t start_time;

struct event_entry {
	struct list_head list;

	u64 time;
	struct perf_evsel *evsel;
	union perf_event *event;
};

static volatile pid_t dump_pid;

static void dump_my_stats(struct perf_session *session)
{
	time_t now;
	struct tm ltime;
	struct mallinfo meminfo;

	printf("\n");

	now = time(NULL);
	if (localtime_r(&now, &ltime)) {
		char date[64];
		strftime(date, sizeof(date), "%Y-%b-%d %H:%M:%S", &ltime);
		printf("%s: ", date);
	}

	printf("Running for %ld seconds\n", now - start_time);

	/* daemon related counters */
	printf("\nDaemon stats:\n"
	       "  events in list: %" PRIu64 "\n"
	       "    event errors: %" PRIu64 "\n"
	       " timstamp errors: %" PRIu64 "\n",
	       num_events, event_errors, timestamp_errors);

	/* information about what was lost - overrun */
	if (session->stats.nr_events[PERF_RECORD_LOST]) {
		printf("  total events lost: %" PRIu64 "\n",
		       session->stats.total_lost);
	}

	if (session->stats.nr_unknown_events) {
		printf("unexpected events: %u\n",
		       session->stats.nr_unknown_events);
	}

	meminfo = mallinfo();
	printf("\nMalloc stats\n"
	       "     total size of allocated memory: %u kB\n"
	       "  total memory handed out by malloc: %u kB\n"
	       "            total memory not in use: %u kB\n"
	       "        number of chunks not in use: %u\n"
	       "   memory releasable by malloc_trim: %u kB\n",
		   meminfo.arena / 1024, meminfo.uordblks / 1024,
		   meminfo.fordblks / 1024, meminfo.ordblks,
		   meminfo.keepcost / 1024);
}

static FILE *open_outfile(void)
{
	FILE *fp;
	char filename[PATH_MAX];

	/* if writing to stdout, nothing to do */
	if (*output_template == '\0')
		return stdout;

	if (snprintf(filename, sizeof(filename), "%s.%ld",
		     output_template, time(NULL)) >= PATH_MAX)
		return NULL;

	if (do_compression) {
		char cmd[PATH_MAX*2];
		snprintf(cmd, sizeof(cmd), "gzip -c > %s.gz", filename);
		fp = popen(cmd, "w");
	} else {
		fp = fopen(filename, "w");
	}

	if (fp == NULL)
		pr_err("Failed to open output file: %d\n", errno);

	return fp;
}

static void close_outfile(FILE *fp)
{
	if (*output_template == '\0')
		return;

	if (do_compression)
		pclose(fp);
}

static void print_event_list(struct perf_sched *sched,
			     struct perf_session *session)
{
	struct perf_tool *tool = &sched->tool;
	struct machine *machine = &session->machines.host;
	struct perf_sample sample;
	struct list_head *l;
	struct event_entry *entry;

	if (list_empty(&event_list)) {
		printf("Odd ... no events to show.\n");
		return;
	}

	if (dump_pid)
		return;

	dump_pid = fork();
	if (dump_pid < 0) {
		printf("Failed to fork child process to dump events\n");
		return;
	} else if (dump_pid)
		return;

	sched->fp = open_outfile();
	if (sched->fp == NULL)
		goto out;

	timehist_header(sched);

	list_for_each(l, &event_list) {
		entry = list_entry(l, struct event_entry, list);
		if (perf_evsel__parse_sample(entry->evsel, entry->event, &sample) ||
			perf_timehist__process_sample(tool, entry->event, &sample,
						      entry->evsel, machine)) {
			printf("Failed to process sample\n");
		}
	}
	fprintf(sched->fp, "\n");

	timehist_print_summary(sched->fp, session);
	fprintf(sched->fp, "\n");
	timehist_pstree(sched->fp, session);

	close_outfile(sched->fp);
out:
	exit(0);
}

static struct event_entry *alloc_entry(struct perf_evsel *evsel, u64 t,
				       union perf_event *event)
{
	struct event_entry *entry;

	entry = malloc(sizeof(struct event_entry));
	if (entry) {
		entry->evsel = evsel;
		entry->time = t;
		/* event was copied to malloc'ed memory when read from mmap */
		entry->event = event;
		num_events++;
	}
	return entry;
}

static void free_entry(struct event_entry *entry)
{
	num_events--;
	free(entry->event);
	free(entry);
}

/* only interested in keeping last N seconds of data */
static void prune_event_list(void)
{
	struct list_head *l, *n;
	struct event_entry *entry;
	u64 tprune;

	if (list_empty(&event_list))
		return;

	/* get timestamp of last entry */
	l = event_list.prev;
	entry = list_entry(l, struct event_entry, list);

	/* back up specified number of seconds */
	tprune = entry->time - time_to_keep;

	/* remove all entries before the prune time */
	list_for_each_safe(l, n, &event_list) {
		entry = list_entry(l, struct event_entry, list);
		if (entry->time > tprune)
			break;

		list_del(l);
		free_entry(entry);
	}

	if (max_events == 0)
		return;

	while (num_events > max_events) {
		list_for_each_safe(l, n, &event_list) {
			entry = list_entry(l, struct event_entry, list);
			list_del(l);
			free_entry(entry);
		}
	}
}

static void free_event_list(void)
{
	struct list_head *l, *n;
	struct event_entry *entry;

	if (list_empty(&event_list))
		return;

	list_for_each_safe(l, n, &event_list) {
		entry = list_entry(l, struct event_entry, list);
		list_del(l);
		free_entry(entry);
	}
}

static int daemon__process_sample(struct perf_tool *tool __maybe_unused,
				  union perf_event *event,
				  struct perf_sample *sample,
				  struct perf_evsel *evsel,
				  struct machine *machine __maybe_unused)
{
	struct event_entry *entry;

	entry = alloc_entry(evsel, sample->time, event);
	if (entry == NULL) {
		pr_err("Failed to allocate memory for event entry\n");
		return -ENOMEM;
	}

	list_add_tail(&entry->list, &event_list);

	return 0;
}

/* called when pulling events out of the mmap buffers */
static int process_event(struct perf_session *session,
			 union perf_event *event,
			 struct perf_sample *sample)
{
	struct machine *machine = &session->machines.host;
	union perf_event *event_copy;
	int err;

	event_copy = malloc(event->header.size);
	memcpy(event_copy, event, event->header.size);

	/* try queueing event */
	err = perf_session_queue_event(session, event_copy, sample, 0);
	if (err == 0)
		return 0;

	free(event_copy);

	if (err == -EINVAL) {
		pr_debug("Sample time below last flush. Dropping.\n");
		timestamp_errors++;
		err = 0;
		goto out;
	}
	if (err != -ETIME) {
		pr_err("Failed to enqueue sample: %d\n", err);
		goto out;
	}

	/* ETIME errors. This really means the sample does not have a
	 * timestamp e.g., no sample_id_all support so non-sample events
	 * do not have timestamps
	 */
	switch (event->header.type) {
	case PERF_RECORD_LOST:
		session->stats.total_lost += event->lost.lost;
		break;
	default:
		err = machine__process_event(machine, event, sample);
	}

out:
	return err;
}

/*
 * process events for a single mmap buffer
 */

#define MAX_EVENTS_PER_MMAP  25

static s64 mmap_read_idx(struct perf_session *session,
			 int idx, u64 *mmap_time)
{
	union perf_event *event;
	struct perf_sample sample;
	s64 n = 0;
	int err;

	*mmap_time = ULLONG_MAX;
	while ((event = perf_evlist__mmap_read(session->evlist, idx)) != NULL) {
		err = perf_evlist__parse_sample(session->evlist, event, &sample);
		if (err) {
			pr_err("Failed to parse event: %d\n", err);
			pr_err("Event type %d\n", event->header.type);
			return -1;
		}

		err = process_event(session, event, &sample);
		if (err)
			return -1;

		/* save time stamp of our first sample for this mmap */
		if (n == 0)
			*mmap_time = sample.time;

		/* limit events per mmap handled all at once */
		n++;
		if (n == MAX_EVENTS_PER_MMAP)
			break;
	}

	return n;
}

/*
 * check each mmap for events to be processed
 */
static int mmap_read(struct perf_tool *tool,
		     struct perf_session *session)
{
	int i, throttled = 0;
	s64 n, ntotal = 0;
	u64 flush_time = ULLONG_MAX, mmap_time;

	for (i = 0; i < session->evlist->nr_mmaps; i++) {
		n = mmap_read_idx(session, i, &mmap_time);
		if (n < 0)
			return -1;

		if (mmap_time < flush_time)
			flush_time = mmap_time;

		ntotal += n;
		if (n == MAX_EVENTS_PER_MMAP)
			throttled = 1;
	}

	/* flush queue after each round in which we processed events */
	if (ntotal) {
		session->ordered_samples.next_flush = flush_time;
		if (tool->finished_round(tool, NULL, session) < 0) {
			pr_err("finished_round failed\n");
			return -1;
		}
	}

	return throttled;
}

static volatile int done, show_events, show_stats;

static void sig_handler(int sig)
{
	if ((sig == SIGINT) || (sig == SIGTERM))
		done = 1;
	else if (sig == SIGHUP)
		show_events = 1;
	else if (sig == SIGUSR1)
		show_stats = 1;
	else if (sig == SIGCHLD) {
		if (waitpid(dump_pid, NULL, WNOHANG) == dump_pid)
			dump_pid = 0;
	}
}

static int daemon_event_loop(struct perf_sched *sched,
			     struct perf_session *session)
{
	struct perf_tool *tool = &sched->tool;
	struct perf_evlist *evlist = session->evlist;
	struct machine *machine = &session->machines.host;
	int rc = 0;

	/* everything is good - enable the events and process */
	perf_evlist__enable(evlist);

	while (!done) {
		/*
		 * read event buffers and process
		 */
		rc = mmap_read(tool, session);
		if (rc < 0) {
			pr_err("mmap_read failed. exiting\n");
			rc = 1;
			break;
		}

		prune_event_list();

		if (show_events) {
			show_events = 0;
			print_event_list(sched, session);
		}
		if (show_stats) {
			show_stats = 0;
			dump_my_stats(session);
		}

		machine__delete_dead_threads(machine);

		/* do not go back to poll if this pass was throttled -- e.g., too
		 * many events on a single mmap. Otherwise wait for 100msec or the
		 * watermark to be reached
		 */
		if (!rc && !done)
			rc = poll(evlist->pollfd, evlist->nr_fds, poll_time);
	}

	perf_evlist__disable(evlist);

	free_event_list();

	return rc;
}

static int open_counters(struct perf_record_opts *opts,
			 struct perf_evlist *evlist, int nr_cpus)
{
	struct perf_evsel *pos;
	int rc = 0;

	perf_evlist__config(evlist, opts);

	list_for_each_entry(pos, &evlist->entries, node) {
		struct perf_event_attr *attr = &pos->attr;

		perf_evsel__save_time(pos, 0, nr_cpus-1);

		/* make sure these are set for all events */
		perf_evsel__set_sample_bit(pos, TID);
		perf_evsel__set_sample_bit(pos, TIME);
		perf_evsel__set_sample_bit(pos, CPU);

		/* and IP/callchain is only set if wanted */
		/* TO-DO: want to add this: strcmp(pos->name, "sched:sched_switch") == 0) { */
		if (opts->call_graph) {
			perf_evsel__set_sample_bit(pos, IP);
			perf_evsel__set_sample_bit(pos, CALLCHAIN);
		} else {
			perf_evsel__reset_sample_bit(pos, IP);
			perf_evsel__reset_sample_bit(pos, CALLCHAIN);
		}

		attr->sample_period = 1;
		attr->freq          = 0;
		attr->watermark     = 0;
		attr->wakeup_events = 100;

		/* will enable all once we are ready */
		attr->disabled = 1;
	}


	perf_evlist__set_id_pos(evlist);

	rc = perf_evlist__open(evlist);
	if (rc < 0) {
		printf("Couldn't create the events: %s\n", strerror(errno));
		goto out;
	}

	rc = perf_evlist__mmap(evlist, opts->mmap_pages, false);
	if (rc < 0) {
		printf("Failed to mmap the events: %s\n", strerror(errno));
		perf_evlist__close(evlist);
		goto out;
	}

	rc = 0;

out:
	return rc;
}

static struct perf_evlist *create_evlist(void)
{
	struct perf_evlist *evlist;

	evlist = perf_evlist__new();
	if (evlist == NULL)
		return NULL;

	if (perf_evlist__add_newtp(evlist, "sched", "sched_switch", timehist_sched_switch_event) ||
	    perf_evlist__add_newtp(evlist, "sched", "sched_wakeup", timehist_sched_wakeup_event) ||
	    perf_evlist__add_newtp(evlist, "sched", "sched_wakeup_new", timehist_sched_wakeup_event)) {
		pr_err("Failed to add sched tracepoints to the event list\n");
		perf_evlist__delete(evlist);
		return NULL;
	}

	return evlist;
}

/* TO-DO: resurrect old patches:
 *   https://lkml.org/lkml/2012/10/8/310
 *   https://lkml.org/lkml/2012/10/8/316
 *
 * This initialization is required if you want to print tracepoint
 * events.
 */
static int perf_evsel__prepare_tracepoint_event(struct perf_evsel *evsel,
						struct pevent *pevent)
{
	struct event_format *event;
	char bf[128];

#if 0
	/* already prepared */
	if (evsel->tp_format)
		return 0;
#endif

	event = pevent_find_event(pevent, evsel->attr.config);
	if (event == NULL)
		return -1;

	if (!evsel->name) {
		snprintf(bf, sizeof(bf), "%s:%s", event->system, event->name);
		evsel->name = strdup(bf);
		if (evsel->name == NULL)
			return -1;
	}

	evsel->tp_format = event;
	return 0;
}

static int perf_evlist__prepare_tracepoint_events(struct perf_evlist *evlist,
						  struct pevent *pevent)
{
	struct perf_evsel *pos;

	list_for_each_entry(pos, &evlist->entries, node) {
		if (pos->attr.type == PERF_TYPE_TRACEPOINT &&
		    perf_evsel__prepare_tracepoint_event(pos, pevent))
			return -1;
	}

	return 0;
}

static int perf_evlist__trace_init(struct perf_evlist *evlist,
			    struct perf_session *session)
{
	struct tracing_data *tdata;
	char temp_file[] = "/tmp/perf-XXXXXXXX";
	int fd;

	fd = mkstemp(temp_file);
	if (fd < 0) {
		pr_err("mkstemp failed\n");
		return -1;
	}
	unlink(temp_file);

	tdata = tracing_data_get(&evlist->entries, fd, false);
	if (!tdata)
		return -1;

	lseek(fd, 0, SEEK_SET);
	(void) trace_report(fd, &session->pevent, false);
	tracing_data_put(tdata);

	return perf_evlist__prepare_tracepoint_events(evlist, session->pevent);
}

static void create_swapper_thread(struct machine *machine)
{
	struct thread *thread = machine__findnew_thread(machine, 0, 0);

	if (thread == NULL || thread__set_comm(thread, "swapper", 0))
		pr_err("problem inserting idle task.\n");

	return;
}

static int perf_sched__daemon(struct perf_sched *sched,
			      int argc, const char **argv)
{
	struct perf_evlist  *evlist;
	struct perf_session *session;
	struct perf_tool *tool = &sched->tool;
	struct machine *machine;
	unsigned int time_opt = MAX_TIME, max_events_opt = MAX_EVENTS;

	struct perf_record_opts opts = {
		.user_interval = 1,
		.mmap_pages    = 1024,  /* 4M per mmap */
		.target = {
		    .uid       = UINT_MAX,
		    .uses_mmap = true,
		    .system_wide = true,
		},
	};

	const char * const my_usage[] = {
		"perf sched daemon [<options>]",
		NULL
	};

	const struct option options[] = {
		OPT_CALLBACK('e', "event", &evlist, "event",
			"additional events to track", parse_events_option),
		OPT_STRING('k', "vmlinux", &symbol_conf.vmlinux_name,
			   "file", "vmlinux pathname"),
		OPT_STRING(0, "kallsyms", &symbol_conf.kallsyms_name,
			   "file", "kallsyms pathname"),
		OPT_UINTEGER('m', "mmap-pages", &opts.mmap_pages,
			     "number of mmap data pages"),
		OPT_CALLBACK_DEFAULT('g', "call-graph", &opts,
			   "mode[,dump_size]", record_callchain_help,
			   &record_parse_callchain_opt, "fp"),
		OPT_UINTEGER('s', "stack-depth", &sched->max_stack,
			     "Maximum number of functions to display backtrace."),
		OPT_STRING('x', "excl", &excl_sym_list_str, "sym[,sym...]",
			   "symbols to skip in backtrace"),
		OPT_STRING(0, "symfs", &symbol_conf.symfs, "directory",
			   "Look for files with symbols relative to this directory"),
		OPT_UINTEGER('t', "time", &time_opt,
			     "Time in seconds to retain in memory. Limits memory consumption."),
		OPT_UINTEGER(0, "max-events", &max_events_opt,
			     "Maximum number of events to retain in memory. Limits memory consumption."),
		OPT_STRING('o', "output", &output_template, "file",
			   "prefix for output filenames (default: stdout); time appended"),
		OPT_BOOLEAN('C', "gz", &do_compression,
			   "write compressed files using gzip"),
		OPT_INCR('v', "verbose", &verbose, "be verbose"),
		OPT_END()
	};

	int err = 0;

	signal(SIGTERM, sig_handler);
	signal(SIGINT,  sig_handler);
	signal(SIGHUP,  sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGCHLD, sig_handler);

	/*
	 *  event handlers for the daemon
	 */
	tool->sample   = daemon__process_sample;
	tool->mmap     = perf_event__process_mmap;
	tool->comm     = perf_event__process_comm;
	tool->exit     = perf_event__process_exit;
	tool->fork     = perf_event__process_fork;
	tool->ordered_samples = true,
	tool->ordering_requires_timestamps = true,
	perf_tool__fill_defaults(tool);


	evlist = create_evlist();
	if (evlist == NULL)
		return -1;

	if (argc) {
		argc = parse_options(argc, argv, options, my_usage, 0);
		if (argc)
			usage_with_options(my_usage, options);
	}

	time_to_keep = (u64) time_opt * NSEC_PER_SEC;
	max_events = (u64) max_events_opt;

	INIT_LIST_HEAD(&event_list);

	if (do_compression && (*output_template == '\0'))
		output_template = "/tmp/sched";

	use_browser = 0;
	setup_browser(false);

	if (setup_excl_sym() < 0)
		return 1;

	symbol_conf.use_callchain = opts.call_graph;
	symbol_conf.nr_events = evlist->nr_entries;
	if (symbol_conf.kallsyms_name == NULL)
		symbol_conf.kallsyms_name = "/proc/kallsyms";

	symbol__init();
	disable_buildid_cache();

	sched->show_cpu_visual = 1;

	session = perf_session__new(NULL, false, NULL);
	if (session == NULL) {
		err = 1;
		goto out;
	}
	session->evlist = evlist;
	machine = &session->machines.host;
	create_swapper_thread(machine);
	machine__create_kernel_maps(machine);
	machines__set_symbol_filter(&session->machines, timehist_symbol_filter);

	if (perf_evlist__create_maps(evlist, &opts.target) < 0) {
		pr_err("Failed to create maps\n");
		err = 1;
		goto out;
	}

	perf_event__synthesize_threads(tool, perf_event__process, machine, false);
	perf_session__set_id_hdr_size(session);

	sched->max_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (sched->max_cpu < 0)
		sched->max_cpu = 1;

	if (init_idle_threads(sched->max_cpu) != 0)
		goto out;

	err = open_counters(&opts, evlist, sched->max_cpu);
	if (err != 0)
		goto out;

	perf_evlist__trace_init(evlist, session);

	start_time = time(NULL);

	err = daemon_event_loop(sched, session);

	perf_evlist__close(evlist);

out:
	if (session)
		perf_session__delete(session);

	perf_evlist__delete_maps(evlist);
	perf_evlist__delete(evlist);

	free_idle_threads();

	return err;
}

/* vim: set ts=4 noexpandtab: */
