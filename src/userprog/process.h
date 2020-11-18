#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
static bool install_page (void *upage, void *kpage, bool writable);
bool load_from_swap (struct spt_entry *spte);
bool load_from_exec (struct spt_entry *spte);
bool load_from_mmap (struct spt_entry *spte);
bool stack_growth (uint8_t *fault_addr);

#endif /* userprog/process.h */
