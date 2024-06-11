#include <libsnoop.h>
#include <filesystem>

#include <blazesym.h>

static struct blaze_symbolizer *symbolizer;

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

int libsnoop_symbolizer_init(void)
{
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Unable to init symbolizer\n");
		return -EINVAL;
	}
	return 0;
}

void libsnoop_symbolizer_release(void)
{
	blaze_symbolizer_free(symbolizer);
}

void libsnoop_stack_symbolize(__u64 *ents, __s32 num_ents, __u32 pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *res;
	const struct blaze_sym *sym;

	if (!num_ents)
		return;

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};

		res = blaze_symbolize_process_abs_addrs(symbolizer, &src,
							(const uintptr_t *)ents,
							num_ents);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};

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

int libsnoop_lookup_lib(const char *name, std::string &path)
{
	char p[4096];

	snprintf(p, sizeof(p), "/lib64/%s", name);
	if (std::filesystem::exists(p))
		goto ok;

	snprintf(p, sizeof(p), "/lib/%s", name);
	if (std::filesystem::exists(p))
		goto ok;

	return -ENOENT;

ok:
	path = p;
	return 0;
}
