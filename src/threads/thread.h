#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"
#include "hash.h"
#include "filesys/directory.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* File Descriptor table. */
#define FD_MAX_SIZE 128                 /* Maximum size of fd_table. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
   //  struct list_elem elem_d;            /* List element for donation list. */

    int64_t tick_to_wake;               /* Ticks at which a thread should wake. */
   //  int old_priority;                   /* Priority which holds original value. */
   //  struct lock *wait_lock;             /* Lock on which this thread is waiting. */
   //  struct list donation_threads;       /* List of threads that donated to this thread. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct list children;               /* List of child process. */
    struct list_elem elem_child;        /* List element for children list. */
    struct file* fd_table[FD_MAX_SIZE]; /* Array of file descriptor.  */

    int status_exit;                    /* Exit status for exit() system call. */
    struct semaphore load_sema;
    struct semaphore exit_sema;         /* Semaphore for synchronization of exiting child. */
    struct semaphore delete_sema;       /* Semaphore for synchronization of deleting child from children. */
   
    bool failed;                        /* Boolean which represents failure of load() function. */
    bool loaded;                        /* Boolean which represents success of load() function. */
#endif

   /* For project #3 */
   struct hash spt;                     /* Supplemental page table entry*/
   int growth_cnt;

   struct file *executable_file;        /* File pointer to process's executable file. */
   struct file *mmap_table[FD_MAX_SIZE];/* Array of memory mapped file pointer. */

   struct dir *current_dir;


   struct dir *directory_table [FD_MAX_SIZE];

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

// /* Own functions for Project #1 */
// int64_t current_closest_tick (void);
// void sleep_thread_with_ticks (int64_t start_tick, int64_t duration_tick);
// void wakeup_thread (void);
// bool priority_compare_func (struct list_elem *elem1, 
//                             struct list_elem *elem2, 
//                             void *aux);

struct thread *get_thread_with_pid(tid_t pid);
void thread_set_killed (void);

int64_t current_closest_tick (void);
void sleep_thread_with_ticks (int64_t start_tick, int64_t duration_tick);
void wakeup_thread (void);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
