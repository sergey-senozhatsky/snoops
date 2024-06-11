#ifndef __LIBSNOOP_H__
#define __LIBSNOOP_H__

#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#define LIBSNOOP_ATTACH_UPROBE(s, pid, obj, prog, opts)				\
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

#define LIBSNOOP_ATTACH_KPROBE(s, prog, sym, opts)				\
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

int libsnoop_symbolizer_init(void);
void libsnoop_symbolizer_release(void);
void libsnoop_stack_symbolize(__u64 *ents, __s32 num_ents, __u32 pid);

int libsnoop_lookup_lib(const char *name, std::string &path);

#endif // __LIBSNOOP_H__
