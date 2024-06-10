// SPDX-License-Identifier: GPL

#ifndef __MEMSNOOP_H__
#define __MEMSNOOP_H__

#define MEMSNOOP_MAX_USTACK_ENTS	8
#define MEMSNOOP_MAX_KSTACK_ENTS	4
#define MEMSNOOP_TASK_COMM_SZ		16

#define ATTR_UNUSED __attribute__((unused))

enum memsnoop_even_type {
	MEMSNOOP_EVENT_INVALID		= 0,
	MEMSNOOP_EVENT_CALL_MALLOC,
	MEMSNOOP_EVENT_RET_MALLOC,
	MEMSNOOP_EVENT_CALL_FREE,
	MEMSNOOP_EVENT_CALL_MMAP,
	MEMSNOOP_EVENT_RET_MMAP,
	MEMSNOOP_EVENT_CALL_MUNMAP,
	MEMSNOOP_EVENT_CALL_PF,
};

struct memsnoop_event {
	__u32	type;
	__s16	num_ustack_ents;
	__s16	num_kstack_ents;
	__u32	pid;
	__u32	tid;
	__s8	comm[MEMSNOOP_TASK_COMM_SZ];
	union {
	        __u64	size;
	        __u64	ptr;
	};
        __u64	ustack_ents[MEMSNOOP_MAX_USTACK_ENTS];
        __u64	kstack_ents[MEMSNOOP_MAX_KSTACK_ENTS];
};

#endif // __MEMSNOOP_H__
