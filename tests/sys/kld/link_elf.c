#include <sys/param.h>
#include <sys/elf.h>
#include <sys/linker.h>
#include <machine/elf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <atf-c.h>

#define EMPTY_FILE		0
#define INVALID_EHDR		1
#define PARTIAL_EHDR		2
#define WRONG_ARCH		3
#define WRONG_CLASS		4
#define UNREADABLE_PHDR		5
#define PARTIAL_PHDR		6
#define INVALID_PHDR		7
#define OVERLAPPING_SEGMENTS	8
#define UNSORTED_SEGMENTS	9
#define MISSING_DYNAMIC		10
#define MEMSZ_LESS_FILESZ	11
#define HUGE_PHNUM		12
#define VADDR_OVERFLOW		13
#define OOB_DYNAMIC		14
#define ZERO_MEMSZ_LOAD		15

static void
make_elf_file(const char *filename, int type)
{
	Elf_Ehdr ehdr;
	Elf_Phdr phdr[3];
	ssize_t ehdrsz, phdrsz;
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "Failed to create %s", filename);

	/*
	 * Create standard ELF header
	 */
	ehdrsz = sizeof(ehdr);
	memset(&ehdr, 0, ehdrsz);

	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_TARG_CLASS;
	ehdr.e_ident[EI_DATA] = ELF_TARG_DATA;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
	ehdr.e_ident[EI_ABIVERSION] = 0;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = ELF_TARG_MACH;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(Elf_Ehdr);
	ehdr.e_phoff = sizeof(Elf_Ehdr);
	ehdr.e_phnum = sizeof(phdr) / sizeof(Elf_Phdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);

	/*
	 * Create program headers
	 */
	phdrsz = sizeof(phdr);
	memset(phdr, 0, phdrsz);

	phdr[0].p_type = PT_LOAD;
	phdr[0].p_vaddr = 0x1000;
	phdr[0].p_memsz = 0x1000;
	phdr[0].p_filesz = 0x1000;

	phdr[1].p_type = PT_LOAD;
	phdr[1].p_vaddr = 0x2000;
	phdr[1].p_memsz = 0x1000;
	phdr[1].p_filesz = 0x1000;

	phdr[2].p_type = PT_DYNAMIC;
	phdr[2].p_vaddr = 0x2000;
	phdr[2].p_memsz = 0x1000;
	phdr[2].p_filesz = 0x1000;

	/*
	 * Inject malformations
	 */
	switch (type) {
	case EMPTY_FILE:
		close(fd);
		return;

	case INVALID_EHDR:
		ehdr.e_ident[EI_MAG0] = 0x42;
		break;

	case PARTIAL_EHDR:
		ehdrsz /= 2;
		break;

	case WRONG_ARCH:
		ehdr.e_machine = (ELF_TARG_MACH == EM_X86_64) ? EM_ARM : EM_X86_64;
		break;

	case WRONG_CLASS:
		ehdr.e_ident[EI_CLASS] = (ELF_TARG_CLASS == ELFCLASS64) ? ELFCLASS32 : ELFCLASS64;
		break;

	case UNREADABLE_PHDR:
		ehdr.e_phoff = PAGE_SIZE * 2;
		break;

	case PARTIAL_PHDR:
		phdrsz -= sizeof(Elf_Phdr) / 2;
		break;

	case INVALID_PHDR:
		ehdr.e_phentsize = sizeof(Elf_Phdr) - 1;
		break;

	case OVERLAPPING_SEGMENTS:
		phdr[0].p_memsz = 0x2000;
		break;

	case UNSORTED_SEGMENTS:
		phdr[0].p_vaddr = 0x3000;
		break;

	case MISSING_DYNAMIC:
		phdr[2].p_type = PT_NULL;
		break;

	case MEMSZ_LESS_FILESZ:
		phdr[0].p_memsz = phdr[0].p_filesz / 2;
		break;

	case HUGE_PHNUM:
		ehdr.e_phnum = 0xffff;
		break;

	case VADDR_OVERFLOW:
		phdr[0].p_vaddr = ~(Elf_Addr)0 - 0x1000;
		phdr[0].p_memsz = 0x2000;
		break;

	case OOB_DYNAMIC:
		phdr[2].p_vaddr = 0x9000;
		break;

	case ZERO_MEMSZ_LOAD:
		phdr[0].p_memsz = 0;
		break;
	}

	ATF_REQUIRE(write(fd, &ehdr, ehdrsz) == ehdrsz);

	if (type != PARTIAL_EHDR) {
		ATF_REQUIRE(write(fd, phdr, phdrsz) == phdrsz);
	}

	close(fd);
}

#define ELF_TC(name, type) \
	ATF_TC(name); \
	ATF_TC_HEAD(name, tc) { \
		atf_tc_set_md_var(tc, "require.user", "root"); \
	} \
	ATF_TC_BODY(name, tc) { \
		const char *mod = "./" #name ".ko"; \
		make_elf_file(mod, type); \
		int res = kldload(mod); \
		ATF_REQUIRE_EQ_MSG(-1, res, "kldload succeeded unexpectedly"); \
		ATF_REQUIRE_EQ_MSG(ENOEXEC, errno, "kldload failed with %d instead of ENOEXEC", errno); \
	}

ELF_TC(elf_empty_file, EMPTY_FILE)
ELF_TC(elf_invalid_ehdr, INVALID_EHDR)
ELF_TC(elf_partial_ehdr, PARTIAL_EHDR)
ELF_TC(elf_wrong_arch, WRONG_ARCH)
ELF_TC(elf_wrong_class, WRONG_CLASS)
ELF_TC(elf_unreadable_phdr, UNREADABLE_PHDR)
ELF_TC(elf_partial_phdr, PARTIAL_PHDR)
ELF_TC(elf_invalid_phdr, INVALID_PHDR)
ELF_TC(elf_overlapping_segments, OVERLAPPING_SEGMENTS)
ELF_TC(elf_unsorted_segments, UNSORTED_SEGMENTS)
ELF_TC(elf_missing_dynamic, MISSING_DYNAMIC)
ELF_TC(elf_memsz_less_filesz, MEMSZ_LESS_FILESZ)
ELF_TC(elf_huge_phnum, HUGE_PHNUM)
ELF_TC(elf_vaddr_overflow, VADDR_OVERFLOW)
ELF_TC(elf_oob_dynamic, OOB_DYNAMIC)
ELF_TC(elf_zero_memsz_load, ZERO_MEMSZ_LOAD)

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, elf_empty_file);
	ATF_TP_ADD_TC(tp, elf_invalid_ehdr);
	ATF_TP_ADD_TC(tp, elf_partial_ehdr);
	ATF_TP_ADD_TC(tp, elf_wrong_arch);
	ATF_TP_ADD_TC(tp, elf_wrong_class);
	ATF_TP_ADD_TC(tp, elf_unreadable_phdr);
	ATF_TP_ADD_TC(tp, elf_partial_phdr);
	ATF_TP_ADD_TC(tp, elf_invalid_phdr);
	ATF_TP_ADD_TC(tp, elf_overlapping_segments);
	ATF_TP_ADD_TC(tp, elf_unsorted_segments);
	ATF_TP_ADD_TC(tp, elf_missing_dynamic);
	ATF_TP_ADD_TC(tp, elf_memsz_less_filesz);
	ATF_TP_ADD_TC(tp, elf_huge_phnum);
	ATF_TP_ADD_TC(tp, elf_vaddr_overflow);
	ATF_TP_ADD_TC(tp, elf_oob_dynamic);
	ATF_TP_ADD_TC(tp, elf_zero_memsz_load);

	return (atf_no_error());
}
