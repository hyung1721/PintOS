#include "page.h"
#include "hash.h"
#include "threads/palloc.h"
/* The hash function for supplemental page hash table. 
   Our supplemental page hash table takes user virtual address
   as a hash value of hash table. By selecting user vitual
   address as a hash value, supplemental page table of each thread
   can manage its own VA-PA mapping supplemental information.*/
uint8_t *
spt_hash_func (struct hash_elem *e)
{
    return hash_entry (e, struct spt_entry, elem)->upage;
}

/* The comparing function for supplemental page hash table.
   This function compares two hash element's upages. */
bool
spt_hash_less_func (struct hash_elem *a,
                    struct hash_elem *b,
                    void *aux)
{
    bool result;

    struct spt_entry *spte_a = hash_entry (a, struct spt_entry, elem);
    struct spt_entry *spte_b = hash_entry (b, struct spt_entry, elem);

    if (spte_a->upage < spte_b->upage)
        result = true;
    else
        result = false;

    return result;
}

/* Initialize supplemental page hash table. */
void
init_spt (struct hash *spt)
{
    hash_init (spt, spt_hash_func, spt_hash_less_func, NULL);
}

/* Get a supplemental page table entry with upage value.
   To find an entry with given upage, we make a temporal supplemental
   page table entry, temp, with given upage and use hash_find ()
   function with current thread's supplemental page table. */
struct spt_entry *
get_spte(uint8_t *upage)
{
    struct hash_iterator i;
    uint8_t *target_upage = pg_round_down (upage);

    hash_first (&i, &thread_current ()->spt);
    while (hash_next (&i))
    {
        struct spt_entry *entry = hash_entry (hash_cur (&i),
                                              struct spt_entry,
                                              elem);
        if (entry->upage == target_upage)
            return entry;
    }
}

struct spt_entry *
create_spte_from_stack (uint8_t *upage)
{
    struct spt_entry *spte = malloc (sizeof (struct spt_entry));
    
    if (!spte)
        return false;

    spte->upage = upage;
    spte->paddr = NULL;
    spte->state = MEMORY; //****
    spte->writable = true;
    spte->thread = thread_current();
    spte->pinned = false;
    spte->mmaped = false;
    hash_insert (&thread_current ()->spt, &spte->elem);

    return spte;
}

/* Update supplemental page table entry with given information.
   An argument state represents the status to which spte->state will
   change.
   
   If state is SWAP_DISK, spte should update its swap_index variable to
   store the information about the location of page in swap disk.*/
void
update_spte (struct spt_entry *spte, enum status state, block_sector_t swap_index)
{
    switch (state)
    {
        case SWAP_DISK:
            spte->paddr = NULL;
            // spte->state = state;
            spte->swap_index = swap_index;
            // pagedir_clear_page (spte->thread->pagedir,
            //                     spte->upage);
            break;
    }
}

/* Free a supplemental page table entry. */
void
destroy_spte (struct hash_elem *e, void *aux)
{
    free (hash_entry (e, struct spt_entry, elem));
}

/* Free a supplemental page hash table.
   This function will be called when the process is terminated. */
void
destroy_spt (struct hash *spt)
{
    // struct hash_iterator i;
    
    // hash_first (&i, spt);

    // while (hash_next (&i))
    // {
    //     struct spt_entry *entry = hash_entry (hash_cur (&i),
    //                                           struct spt_entry,
    //                                           elem);
    //     if(entry->state = MEMORY){

    //         palloc_free_page (entry->paddr);
    //         pagedir_clear_page (entry->thread->pagedir,
    //                         entry->upage);
    //     }
       
    // }

    hash_destroy (spt, destroy_spte);
}

/* Cretae a supplemental page table entry with given information about
   executables. This function is used in load_segment() to create 
   appropriate supplemental page table entry for each loaded segment. */
struct spt_entry *
create_spte_from_exec (struct file *file, int32_t ofs,
                       uint8_t *upage, uint32_t read_bytes,
                       uint32_t zero_bytes, bool writable)
{
    struct spt_entry *spte = malloc (sizeof (struct spt_entry));

    if (!spte)
        return false;

    spte->upage = upage;
    spte->paddr = NULL;
    spte->state = EXEC_FILE;
    spte->writable = writable;
    spte->thread = thread_current();
    spte->pinned = false;
    spte->mmaped = false;
    spte->file = file;
    spte->offset = ofs;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    hash_insert (&thread_current ()->spt, &spte->elem);

    return spte;
}

struct spt_entry *
create_spte_from_mmap(struct file *file, int32_t offset,
                       uint8_t *addr, uint32_t read_bytes,
                       uint32_t zero_bytes, bool writable)
{
    struct spt_entry *spte = malloc (sizeof (struct spt_entry));

    if (!spte)
        return false;

    spte->upage = addr;
    spte->paddr = NULL;
    spte->state = MMAP;
    spte->writable = writable;
    spte->thread = thread_current();
    spte->pinned = false;
    spte->mmaped = true;
    spte->file = file;
    spte->offset = offset;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    hash_insert (&thread_current ()->spt, &spte->elem);

    return spte;
}

void
pin_page (void *buffer, unsigned size)
{
    struct thread *current_thread = thread_current ();
    struct hash spt = current_thread->spt;
    bool load;
    void *current_upage;

    for (current_upage = pg_round_down(buffer); current_upage < buffer + size; current_upage += PGSIZE)
    {
        struct spt_entry *spte = get_spte(current_upage);
        if (spte)
        {
            if (spte->state == EXEC_FILE)
            {
            load = load_from_exec(spte);
            }
            else if (spte->state == SWAP_DISK)
            {  
            load = load_from_swap (spte);
            }
            else if (spte->state == MMAP)
            {
            load = load_from_mmap(spte);
            }

            if (spte->state == MEMORY)
                spte->pinned = true;
            else
                printf("Pinning failed in pin_page()\n");
        }

    }

}

void
unpin_page (void *buffer, unsigned size)
{
    struct thread *current_thread = thread_current ();
    struct hash spt = current_thread->spt;
    void *current_upage;

    for (current_upage = pg_round_down(buffer); current_upage < buffer + size; current_upage += PGSIZE)
    {
        struct spt_entry *spte = get_spte(current_upage);
        
        if(spte)
        {
            spte->pinned = false;
        }
    }
}