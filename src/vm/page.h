#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "devices/block.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"

enum status {
    SWAP_DISK,                    /* Frame is in swap disk. */
    MEMORY,                       /* Frame is in physical memory. */
    EXEC_FILE,                     /* Frame is executable file. */
    MMAP                          
};

struct spt_entry {
    struct hash_elem elem;        /* Hash element for hash table. */

    /* For project #3-1. */
    enum status state;            /* Status of frame. */
    void *upage;                  /* User virtual address. */
    void *paddr;                  /* Physical address. */

    bool writable;                /* Writable page or not. */
    struct thread *thread;        /* Thread which controls this entry.*/

    block_sector_t swap_index;    /* Location of frame in swap disk. */

    /* For lazy loading part of project #3-2. */
    struct file *file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
};


void init_spt (struct hash *spt);
struct spt_entry *get_spte (uint8_t *upage);
void update_spte (struct spt_entry *spte, enum status state, block_sector_t swap_index);
struct spt_entry *create_spte_from_stack (uint8_t *upage);
struct spt_entry *create_spte_from_exec (struct file *file, int32_t ofs,
                                         uint8_t *upage, uint32_t read_bytes,
                                         uint32_t zero_bytes,
                                        bool writable);

struct spt_entry * create_spte_from_mmap(struct file *file, int32_t offset,
                       uint8_t *addr, uint32_t read_bytes,
                       uint32_t zero_bytes, bool writable);
void destroy_spte (struct hash_elem *e, void *aux);
void destroy_spt (struct hash *spt);

#endif