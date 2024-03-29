#include "swap.h"
#include "bitmap.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

/* 1-1 mapping from swap_table to swap disk blocks. */
struct bitmap *swap_table;
struct lock swap_lock;
struct block *swap_disk;

/* Initialize swap table and lock. After locate_block_devices() in init.c,
   this function will be called. */
void
init_swap (void)
{
    swap_disk = block_get_role (BLOCK_SWAP);
    block_sector_t block_count = block_size (swap_disk);
    swap_table = bitmap_create (block_count);
    lock_init (&swap_lock);
}

/* Evict victim_frame to swap disk.
   
   1. Find free index from swap disk with eigth blocks.
   2. Write victim_frame to swap disk with free index. */
block_sector_t
swap_out (void *victim_frame)
{
    lock_acquire (&swap_lock);
    block_sector_t free_index = bitmap_scan_and_flip (swap_table, 0, 8, false);

    if (free_index == BITMAP_ERROR)
    {
        ASSERT("NO free index in swap disk");
    } 

    for (int i = 0; i < 8; i++)
    {
        block_write (swap_disk, free_index + i,
                    (uint8_t *)victim_frame + i * BLOCK_SECTOR_SIZE);
    }

    lock_release (&swap_lock);
    return free_index;
}

/* Bring frame from swap disk. 
   
   1. Check validity of swap_index in swap_table.
   2. If valid, initialize swap_table
   3. Read 8 blocks from swap disk to frame.*/
void
swap_in (block_sector_t swap_index, void *frame)
{
    
    lock_acquire (&swap_lock);

    if (bitmap_test (swap_table, swap_index) == false)
    {
        ASSERT ("Trying to swap in a free block.");
    }

    for (int i = 0; i < 8; i++)
    {
        bitmap_flip (swap_table, swap_index+i);
        block_read (swap_disk, swap_index + i,
                   (uint8_t *) frame + i * BLOCK_SECTOR_SIZE);
    }

    lock_release (&swap_lock);
}


/* Find victime frame from frame_table. 
   This function follows 'second chance' policy. */
struct ft_entry *
find_victim (void)
{ 
    struct list_elem *evict_elem = list_pop_back(&frame_table);

    while (true)
    {

        struct ft_entry *entry = list_entry (evict_elem, struct ft_entry, elem);
        
        /* If current frame is pinned, it must not be evicted. */
        if (entry->spte->pinned)
            continue;
        
        /* If current entry is not accessed, choose this entry as a
           victim frame. If not, set access bit zero and continue.

           If all entry is accessed, first  inserted entry will become
           a vitime frame. */
        if (!pagedir_is_accessed (entry->t->pagedir, entry->spte->upage))
        {
            entry->spte->state = SWAP_DISK;
            pagedir_clear_page (entry->spte->thread->pagedir,
                                entry->spte->upage);

            if (entry->spte->mmaped 
                && pagedir_is_dirty(entry->t->pagedir, entry->spte->upage))
            {
                lock_acquire (&filesys_lock);
                file_write_at (entry->spte->file, entry->frame, 
                               entry->spte->read_bytes,
                               entry->spte->offset);
                lock_release (&filesys_lock);
            }

            return list_entry (evict_elem, struct ft_entry, elem); 
        }
        else
        {
            pagedir_set_accessed (entry->t->pagedir, entry->spte->upage, 0);
            list_push_front (&frame_table, evict_elem);
            evict_elem = list_pop_back (&frame_table);
        }
    }
}

