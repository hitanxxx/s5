#ifndef _MEM_H_INCLUDED_
#define _MEM_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

///#define MEM_BY_SYSCALL

void *sys_alloc(int size);
void sys_free(void *addr);

int mem_free(void *addr);
void *mem_alloc(int size);
int mem_exit();
int mem_init();
char *mem_ver();

#ifdef __cplusplus
}
#endif

#endif
