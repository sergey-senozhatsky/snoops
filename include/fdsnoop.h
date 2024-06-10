#ifndef __FDSNOOP_H__
#define __FDSNOOP_H__

#define FDSNOOP_MAX_USTACK_ENTS		8
#define FDSNOOP_TASK_COMM_SZ		16

#define ATTR_UNUSED __attribute__((unused))

enum fdsnoop_even_type {
	FDSNOOP_EVENT_INVALID		= 0,
	FDSNOOP_EVENT_RET_OPEN,
	FDSNOOP_EVENT_RET_DUP,
	FDSNOOP_EVENT_CALL_CLOSE,
};

struct fdsnoop_event {
	__u32	type;
        __s32	fd;
	__u32	pid;
	__u32	tid;
	__s8	comm[FDSNOOP_TASK_COMM_SZ];
	__s16	num_ustack_ents;
        __u64	ustack_ents[FDSNOOP_MAX_USTACK_ENTS];
};

#endif // __FDSNOOP_H__
