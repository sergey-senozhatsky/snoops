#include <getopt.h>
#include <limits.h>
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
#include <blazesym.h>
#include <memsnoop.h>
#include <memsnoop.skel.h>

static struct blaze_symbolizer *symbolizer;

static struct option long_options[] = {
	{"pid",		required_argument,	0,	'p'},
	{0, 0, 0, 0}
};

#define ATTACH_UPROBE(s, pid, obj, prog, opts)					\
	do {									\
		printf("Attaching uprobe: " #prog "\n");			\
		if (s->links.prog) {						\
			fprintf(stderr, "Already attached: " #prog "\n");	\
			return -EINVAL;						\
		}								\
		s->links.prog = bpf_program__attach_uprobe_opts(s->progs.prog,	\
								(pid),		\
								(obj),		\
								0,		\
								(opts));	\
		if (!s->links.prog) {						\
			perror("Failed to attach: " #prog);			\
			return -EINVAL;						\
		}								\
	} while (false)

#define ATTACH_KPROBE(s, prog, sym, opts)					\
	do {									\
		printf("Attaching kprobe: " #prog "\n");			\
		if (s->links.prog) {						\
			fprintf(stderr, "Already attached: " #prog "\n");	\
			return -EINVAL;						\
		}								\
		s->links.prog = bpf_program__attach_kprobe_opts(s->progs.prog,	\
								(sym),		\
								(opts));	\
		if (!s->links.prog) {						\
			perror("Failed to attach: " #prog);			\
			return -EINVAL;						\
		}								\
	} while (false)


static const char *libc_path(void)
{
	return "/lib64/libc.so.6";
}

static int attach_probes(struct memsnoop_bpf *snoop, int pid)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uopts);

	uopts.func_name = "malloc";
	uopts.retprobe = false;
	ATTACH_UPROBE(snoop, pid, libc_path(), call_malloc, &uopts);

	uopts.func_name = "malloc";
	uopts.retprobe = true;
	ATTACH_UPROBE(snoop, pid, libc_path(), ret_malloc, &uopts);

	uopts.func_name = "mmap";
	uopts.retprobe = false;
	ATTACH_UPROBE(snoop, pid, libc_path(), call_mmap, &uopts);

	uopts.func_name = "mmap";
	uopts.retprobe = true;
	ATTACH_UPROBE(snoop, pid, libc_path(), ret_mmap, &uopts);

	uopts.func_name = "munmap";
	uopts.retprobe = false;
	ATTACH_UPROBE(snoop, pid, libc_path(), call_munmap, &uopts);

	uopts.func_name = "free";
	uopts.retprobe = false;
	ATTACH_UPROBE(snoop, pid, libc_path(), call_free, &uopts);

	LIBBPF_OPTS(bpf_kprobe_opts, kopts);
	kopts.retprobe = false;
	ATTACH_KPROBE(snoop, call_handle_mm_fault, "handle_mm_fault", &kopts);

	return 0;
}

static void frame(const char *name, uintptr_t input_addr, uintptr_t addr,
		  uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	printf("%16s  %s", "", name);
	if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
	else if (code_info != NULL && code_info->file != NULL)
		printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
	else
		printf("[inlined]\n");
}

static void inlined_frame(const char *name, uintptr_t input_addr, uintptr_t addr,
			  uint64_t offset, const blaze_symbolize_code_info* code_info)
{
	printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
	if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
	else if (code_info != NULL && code_info->file != NULL)
		printf(" %s:%u\n", code_info->file, code_info->line);
	else
		printf("\n");
}

static void show_stack_trace(struct memsnoop_event *event)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *res;
	const struct blaze_sym *sym;
	__u16 num_ents;
	__u64 *ents;

	if (event->pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = event->pid,
		};

		ents = event->ustack_ents;
		num_ents = event->num_ustack_ents;

		if (!num_ents)
			return;

		res = blaze_symbolize_process_abs_addrs(symbolizer, &src,
							(const uintptr_t *)ents,
							num_ents);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};

		ents = event->ustack_ents;
		num_ents = event->num_ustack_ents;

		if (!num_ents)
			return;

		res = blaze_symbolize_kernel_abs_addrs(symbolizer, &src,
						       (const uintptr_t *)ents,
						       num_ents);
	}

	for (size_t i = 0; i < num_ents; i++) {
		if (!res || res->cnt <= i || !res->syms[i].name) {
			printf("%016llx: <no-symbol>\n", ents[i]);
			continue;
		}

		sym = &res->syms[i];
		frame(sym->name, ents[i], sym->addr, sym->offset, &sym->code_info);

		for (size_t j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			inlined_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	printf("\n");
	blaze_result_free(res);
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

	show_stack_trace(event);
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

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Failed to create a symbolizer\n");
		err = -EINVAL;
		goto cleanup;
	}

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
	blaze_symbolizer_free(symbolizer);
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
