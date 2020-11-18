#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/pte.h"

typedef int mapid_t;

void syscall_init (void);

void syscall_exit (int status);

#endif /* userprog/syscall.h */
