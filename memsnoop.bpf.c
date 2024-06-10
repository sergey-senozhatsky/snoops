#include <errno.h>
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf_perf_event.h>

#include <memsnoop.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024);
} rb SEC(".maps");

const volatile __u32 kprobe_snoop_pid = 0;

static int ustack(struct pt_regs *ctx, struct memsnoop_event *event)
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

ATTR_UNUSED
static int kstack(struct pt_regs *ctx, struct memsnoop_event *event)
{
	event->num_kstack_ents = bpf_get_stack(ctx,
					       event->kstack_ents,
					       sizeof(event->kstack_ents),
					       0);
	if (event->num_kstack_ents < 0)
		return -EINVAL;

	event->num_kstack_ents /= sizeof(event->kstack_ents[0]);
	return 0;
}

static struct memsnoop_event *bpf_ringbuf_event_get(void)
{
	struct memsnoop_event *event;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return NULL;

	event->type = MEMSNOOP_EVENT_INVALID;
	event->num_ustack_ents = 0;
	event->num_kstack_ents = 0;
	return event;
}

static int memsnoop_event(struct pt_regs *ctx,
			  enum memsnoop_even_type type,
			  __u64 val)
{
	struct memsnoop_event *event;
	__u64 id;

	event = bpf_ringbuf_event_get();
	if (!event)
		return -ENOMEM;

	id = bpf_get_current_pid_tgid();
	event->pid = id >> 32;
	event->tid = (__u32)id;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (type == MEMSNOOP_EVENT_CALL_MALLOC ||
	    type == MEMSNOOP_EVENT_CALL_MMAP) {
		if (ustack(ctx, event)) {
			bpf_ringbuf_submit(event, 0);
			return -EINVAL;
		}
	}

	event->type = type;
	event->size = val;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(call_malloc, size_t size)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_CALL_MALLOC, size);
}

SEC("uretprobe")
int BPF_URETPROBE(ret_malloc)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_RET_MALLOC, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(call_mmap, void *addr, size_t size)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_CALL_MMAP, size);
}

SEC("uretprobe")
int BPF_URETPROBE(ret_mmap)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_RET_MMAP, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(call_munmap, void *ptr)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_CALL_MUNMAP, (__s64)ptr);
}

SEC("uprobe")
int BPF_UPROBE(call_free, void *ptr)
{
	return memsnoop_event(ctx, MEMSNOOP_EVENT_CALL_FREE, (__s64)ptr);
}

struct vm_area_struct;

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(call_handle_mm_fault, struct vm_area_struct *vma,
	       unsigned long ptr)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != kprobe_snoop_pid)
		return 0;

	return memsnoop_event(ctx, MEMSNOOP_EVENT_CALL_PF, (__s64)ptr);
}

char LICENSE[] SEC("license") = "GPL";
