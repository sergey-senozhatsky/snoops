// SPDX-License-Identifier: GPL

#include <errno.h>
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf_perf_event.h>

#include <fdsnoop.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024);
} rb SEC(".maps");

static int ustack(struct pt_regs *ctx, struct fdsnoop_event *event)
{
	event->num_ustack_ents = bpf_get_stack(ctx,
					       event->ustack_ents,
					       sizeof(event->ustack_ents),
					       BPF_F_USER_STACK);

	if (event->num_ustack_ents < 0)
		return -EINVAL;

	event->num_ustack_ents /= sizeof(event->ustack_ents[0]);
	return 0;
}

static struct fdsnoop_event *bpf_ringbuf_event_get(void)
{
	struct fdsnoop_event *event;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return NULL;

	event->type = FDSNOOP_EVENT_INVALID;
	event->num_ustack_ents = 0;
	return event;
}

static int fdsnoop_event(struct pt_regs *ctx,
			 enum fdsnoop_even_type type,
			 __s32 fd)
{
	struct fdsnoop_event *event;
	__u64 id;

	event = bpf_ringbuf_event_get();
	if (!event)
		return -ENOMEM;

	id = bpf_get_current_pid_tgid();
	event->pid = id >> 32;
	event->tid = (__u32)id;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (type == FDSNOOP_EVENT_RET_OPEN ||
	    type == FDSNOOP_EVENT_RET_DUP) {
		if (ustack(ctx, event)) {
			bpf_ringbuf_submit(event, 0);
			return -EINVAL;
		}
	}

	event->type = type;
	event->fd = fd;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uretprobe")
int BPF_UPROBE(ret_open)
{
	return fdsnoop_event(ctx, FDSNOOP_EVENT_RET_OPEN, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_URETPROBE(ret_dup)
{
	return fdsnoop_event(ctx, FDSNOOP_EVENT_RET_DUP, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(call_close, __s32 fd)
{
	return fdsnoop_event(ctx, FDSNOOP_EVENT_CALL_CLOSE, fd);
}

char LICENSE[] SEC("license") = "GPL";
