#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "page.h"

struct ft_entry
{
    struct list_elem elem;

    void *frame;                /* The address of frame. */
    struct spt_entry *spte;     /* Connected spt_entry. */
    struct thread *t;           /* The thread which has a mapping to frame. */
};

extern struct list frame_table;

void init_frame_table (void);
void *frame_alloc (enum palloc_flags flags, struct spt_entry *spte);
struct ft_entry *create_fte (void *frame, struct spt_entry *spte);
void free_frame_entry (struct thread *cur);

#endif