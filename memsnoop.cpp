// SPDX-License-Identifier: GPL

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <chrono>
#include <string>
#include <iostream>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libsnoop.h>
#include <memsnoop.h>
#include <memsnoop.skel.h>

static struct option long_options[] = {
	{"pid",		required_argument,	0,	'p'},
	{0, 0, 0, 0}
};

static int attach_probes(struct memsnoop_bpf *snoop, int pid)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uopts);
	std::string libc;

	if (libsnoop_lookup_lib("libc.so.0", libc))
		return -ENOENT;

	uopts.func_name = "malloc";
	uopts.retprobe = false;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), call_malloc, &uopts);

	uopts.func_name = "malloc";
	uopts.retprobe = true;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), ret_malloc, &uopts);

	uopts.func_name = "mmap";
	uopts.retprobe = false;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), call_mmap, &uopts);

	uopts.func_name = "mmap";
	uopts.retprobe = true;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), ret_mmap, &uopts);

	uopts.func_name = "munmap";
	uopts.retprobe = false;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), call_munmap, &uopts);

	uopts.func_name = "free";
	uopts.retprobe = false;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc.c_str(), call_free, &uopts);

	LIBBPF_OPTS(bpf_kprobe_opts, kopts);
	kopts.retprobe = false;
	LIBSNOOP_ATTACH_KPROBE(snoop, call_handle_mm_fault, "handle_mm_fault",
			       &kopts);

	return 0;
}

static int handle_memsnoop_event(void *ctx, void *data, size_t data_sz)
{
	struct memsnoop_event *event = (struct memsnoop_event *)data;

	printf("comm: %s pid:%d event: ", event->comm, event->pid);
	switch (event->type) {
	case MEMSNOOP_EVENT_CALL_MALLOC:
		printf("malloc() sz=%llu\n", event->size);
		break;
	case MEMSNOOP_EVENT_RET_MALLOC:
		printf("malloc() ptr=%p\n", (void *)event->ptr);
		break;
	case MEMSNOOP_EVENT_CALL_FREE:
		printf("free() ptr=%p\n", (void *)event->ptr);
		break;
	case MEMSNOOP_EVENT_CALL_MMAP:
		printf("mmap() sz=%llu\n", event->size);
		break;
	case MEMSNOOP_EVENT_RET_MMAP:
		printf("mmap() ptr=%p\n", (void *)event->ptr);
		break;
	case MEMSNOOP_EVENT_CALL_MUNMAP:
		printf("munmap() ptr=%p\n", (void *)event->ptr);
		break;
	case MEMSNOOP_EVENT_CALL_PF:
		printf("handle_mm_fault() ptr=%p\n", (void *)event->ptr);
		break;

	case MEMSNOOP_EVENT_INVALID:
		printf("INVALID\n");
		return -EINVAL;
	};

	libsnoop_stack_symbolize(event->ustack_ents, event->num_ustack_ents,
				 event->pid);
	libsnoop_stack_symbolize(event->kstack_ents, event->num_kstack_ents,
				 0);
	return 0;
}

static int memsnoop(pid_t pid)
{
	struct ring_buffer *rb = NULL;
	struct memsnoop_bpf *snoop;
	int err;

	snoop = memsnoop_bpf__open();
	if (!snoop) {
		fprintf(stderr, "Failed to open BPF snoop\n");
		return -EINVAL;
	}

	snoop->rodata->kprobe_snoop_pid = pid;
	err = memsnoop_bpf__load(snoop);
	if (err) {
		fprintf(stderr, "Failed tp load BPF snoop\n");
		goto cleanup;
	}

	err = libsnoop_symbolizer_init();
	if (err)
		goto cleanup;

	err = attach_probes(snoop, pid);
	if (err)
		goto cleanup;

	rb = ring_buffer__new(bpf_map__fd(snoop->maps.rb),
			      handle_memsnoop_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to open ring buffer\n");
		err = -EINVAL;
		goto cleanup;
	}

	while ((err = ring_buffer__poll(rb, -1)) >= 0) {
	}

cleanup:
	ring_buffer__free(rb);
	memsnoop_bpf__destroy(snoop);
	libsnoop_symbolizer_release();
	return err;
}

int main(int argc, char **argv)
{
	pid_t pid = -1;
	int c;

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "t:p:",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			pid = std::stol(optarg);
			break;
		default:
			abort();
		}
	}

	return memsnoop(pid);
}
