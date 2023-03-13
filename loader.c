/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int fd;
static struct sigaction old_action;

static so_seg_t get_seg(const void *address) {
	so_seg_t segment;
	int i;
	uintptr_t addr = (uintptr_t)address;

	/* Se percurg segmentele executabilului */
	for (i = 0; i < exec->segments_no; i++) {

		segment = exec->segments[i];

		/* Se verifica daca segmentul contine adresa care a cauzat page fault-ul */
		if (addr >= segment.vaddr && addr < segment.vaddr + segment.mem_size) {
			return segment;
		}
	}

	/* In caz contrar, adresa nu se afla in niciun segment */

	segment.vaddr = UINTPTR_MAX;
	return segment;
}


/* Functie pentru zeroizare a zonei de memorie dupa mapare */

static void make_zeros(so_seg_t segment, char *addr, int len) {

	char *addr_start = addr;
	char *addr_first = (char *)segment.vaddr + segment.file_size;
	char *addr_last = (char *)segment.vaddr + segment.mem_size;
	int length = len;

	if (addr_first > addr + len)
		return;

	if (addr_first > addr) {

		addr_start = addr_first;

		if (addr + len <= addr_last)
			length = (addr + len) - addr_start;
		else
			length = addr_last - addr_start;
	}

	memset((void *)addr_start, 0, length);
}


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	int page_size, page_index, offset, ok = 0;
	void *fault;
	char *map, *aligned;
	so_seg_t segment;

	/* Dimensiunea unei pagini */
	page_size = getpagesize();

	/* Adresa care a cauzat page fault-ul */
	fault = info->si_addr;

	/* Se pargurge segment cu segment */
	segment = get_seg(info->si_addr);

	if (segment.vaddr != UINTPTR_MAX) {

		offset = segment.offset;

		/* Indexul paginii */
		page_index = ((int)fault - segment.vaddr);
		page_index = page_index / page_size;

		/* Page fault-ul vine dintr-un segment cunoscut */
		ok = 1;

		/* Daca pagina este deja mapata, se apeleaza handler-ul default */
		if (((int *)segment.data)[page_index] == 1) {

			old_action.sa_sigaction(signum, info, context);
			return;
		}

		/* Se marcheaza pagina curenta ca fiind mapata */
		((int *)segment.data)[page_index] = 1;

		/* Se aliniaza adresa unde trebuie mapata pagina */
		aligned = (char *)segment.vaddr + page_index * page_size;


		/* Se mapeaza pagina */
		map = mmap(aligned, page_size, segment.perm, MAP_FIXED | MAP_PRIVATE, fd, offset + page_index * page_size);
		if (map == MAP_FAILED) {
			perror("Mmap failed");
			return;
		}


		/* Se apeleaza functia anterioara pentru zeroizare */
		make_zeros(segment, map, page_size);


		/* Se schimba permisiunile paginii, ea trebuind sa aiba aceleasi
		 * permisiuni cu segmentul din care face parte
		 */
		mprotect(map, page_size, segment.perm);

		return;

		}
	/* Se foloseste vechiul handler pentru un page fault care nu face
	 * parte dintr-un segment cunoscut
	 */
	if (ok == 0) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	int pages;

	int i;

	int pagesize = getpagesize();

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("Open failed");
		return -1;
	}

	/* Se aloca memorie pentru vectorul care in care se tine cont de
	 * paginile deja mapate din fiecare segment
	 */
	for (i = 0; i < exec->segments_no; i++) {

		/** Numarul de pagini din segment **/
		pages = exec->segments[i].mem_size / pagesize;

		/* Se aloca un vector pentru retinerea paginilor ca fiind
		 * mapate sau nemapate
		 */
		exec->segments[i].data = calloc(pages, sizeof(int));
		if (exec->segments[i].data == NULL) {
			perror("calloc");
			return -1;
		}
	}
	so_start_exec(exec, argv);

	return -1;
}
