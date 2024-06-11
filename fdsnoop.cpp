// SPDX-License-Identifier: GPL

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <string>
#include <iostream>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libsnoop.h>
#include <fdsnoop.h>
#include <fdsnoop.skel.h>

static struct option long_options[] = {
	{"pid",		required_argument,	0,	'p'},
	{0, 0, 0, 0}
};

static const char *libc_path(void)
{
	return "/lib64/libc.so.6";
}

static int attach_probes(struct fdsnoop_bpf *snoop, int pid)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uopts);

	uopts.func_name = "open";
	uopts.retprobe = true;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc_path(), ret_open, &uopts);

	uopts.func_name = "dup";
	uopts.retprobe = true;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc_path(), ret_dup, &uopts);

	uopts.func_name = "close";
	uopts.retprobe = false;
	LIBSNOOP_ATTACH_UPROBE(snoop, pid, libc_path(), call_close, &uopts);

	return 0;
}

static int handle_fdsnoop_event(void *ctx, void *data, size_t data_sz)
{
	struct fdsnoop_event *event = (struct fdsnoop_event *)data;

	printf("comm: %s pid:%d event: ", event->comm, event->pid);
	switch (event->type) {
	case FDSNOOP_EVENT_RET_OPEN:
		printf("open() fd=%d\n", event->fd);
		break;
	case FDSNOOP_EVENT_RET_DUP:
		printf("dup() fd=%d\n", event->fd);
		break;
	case FDSNOOP_EVENT_CALL_CLOSE:
		printf("close() fd=%d\n", event->fd);
		break;

	case FDSNOOP_EVENT_INVALID:
		printf("INVALID\n");
		return -EINVAL;
	};

	libsnoop_stack_symbolize(event->ustack_ents, event->num_ustack_ents,
				 event->pid);
	return 0;
}

static int fdsnoop(pid_t pid)
{
	struct ring_buffer *rb = NULL;
	struct fdsnoop_bpf *snoop;
	int err;

	snoop = fdsnoop_bpf__open();
	if (!snoop) {
		fprintf(stderr, "Failed to open BPF snoop\n");
		return -EINVAL;
	}

	err = fdsnoop_bpf__load(snoop);
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
			      handle_fdsnoop_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to open ring buffer\n");
		err = -EINVAL;
		goto cleanup;
	}

	while ((err = ring_buffer__poll(rb, -1)) >= 0) {
	}

cleanup:
	ring_buffer__free(rb);
	fdsnoop_bpf__destroy(snoop);
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

	return fdsnoop(pid);
}
