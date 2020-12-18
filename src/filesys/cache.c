#include <stdlib.h>
#include "cache.h"
#include "filesys.h"
#include "debug.h"
#include "string.h"
#include "inode.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "lib/kernel/list.h"

#define MAX_CACHE_SIZE 64
#define CACHE_MISS -1
#define PERIOD_WRITE_BEHIND 30

/* Structure for buffer cache slot.
   
   The slot entry contains bit information and data for
   block with sector number. */
struct cache_slot
{
    bool used;                       // Used slot or not.
    bool dirty;                      // Dirty bit.
    bool accessed;                   // Accessed bit.

    int index;                       // Index for the slot.

    uint8_t data[BLOCK_SECTOR_SIZE]; // Cached block data.
    block_sector_t sector;           // Original block sector index.
};

/* Structure for read-ahead block entry.

   For the read-ahead functionality, we need
   a data structure for memorizing some information
   about the block which should be loaded soon.
   The ahead_block contains such information, sector
   number and which inode is related to this ahead_block. */
struct ahead_block
{
    block_sector_t sector;          // Sector number.
    struct inode* inode;            // Inode pointer.
    struct list_elem elem;          // List element.
};

/* We select the data structure, fixed-size
   array, for buffer cache. */
struct cache_slot buffer_cache[MAX_CACHE_SIZE];
int hand_index = 0;                 // For clock algorithm.

struct list ahead_list;
struct semaphore ahead_list_sema;

struct lock buffer_cache_op_lock;
struct lock buffer_cache_lock[MAX_CACHE_SIZE];

void write_behind (void);
void read_ahead (void);

/* Initializes the buffer cache.

   Before File system initialization, this
   function is performed.*/
void
buffer_cache_init (void)
{
    lock_init (&buffer_cache_op_lock);

    for (int i = 0; i < MAX_CACHE_SIZE; i++)
    {
        buffer_cache[i].used = false;
        buffer_cache[i].index = i;

        lock_init (&buffer_cache_lock[i]); 
    }

    list_init (&ahead_list);
    sema_init(&ahead_list_sema, 0);
    
    /* Create a thread which does write-behind periodically. */
    thread_create ("write-behind", PRI_DEFAULT, write_behind, NULL);

    /* Create a thread which does read-ahead. */
    thread_create ("read-ahead", PRI_DEFAULT, read_ahead, NULL);
}

/* Returns the cache index for cach block corresponding
   to SECTOR number.
   If there is no such block, returns CACHE_MISS(-1).*/
int
get_buffer_cache_index (block_sector_t sector)
{
    for (int i = 0; i < MAX_CACHE_SIZE; i++)
    {
        if (buffer_cache[i].used && buffer_cache[i].sector == sector)
            return i;
    }
    return CACHE_MISS;
}

/* Return available cache block. 

   If there is no available cache block, do eviction
   process based on clock algorithm and return evicted
   cache block. */
struct
cache_slot* cache_slot_alloc (void)
{
    while (1)
    {
        struct cache_slot* current_slot = &buffer_cache[hand_index];
        
        if (!current_slot->used)
        {
            lock_acquire (&buffer_cache_lock[current_slot->index]);
            hand_index = (hand_index + 1) % MAX_CACHE_SIZE;
            return current_slot;
        } 
            
        if(current_slot->accessed)
        {
            current_slot->accessed = false;
            hand_index = (hand_index + 1) % MAX_CACHE_SIZE;
        }
        else
        {
            /* Eviction process. */
            lock_acquire (&buffer_cache_lock[current_slot->index]);
            if (current_slot->dirty)
            {
                block_write (fs_device, current_slot->sector, current_slot->data);
            }            
            current_slot->used = false;
            current_slot->accessed = false;
            current_slot->dirty = false;

            hand_index = (hand_index + 1) % MAX_CACHE_SIZE;
            return current_slot;
        }
    }
    ASSERT(0); // should not come
}

/* Read cache block for SECTOR_IDX with SECTOR_OFS to BUFFER 
   starting at BYTES_WRITTEN of length CHUNK_SIZE. 
   INODE pointer is needed for read-ahead functionality. */
void cache_read (void *buffer , block_sector_t sector_idx, 
                 off_t bytes_read, int sector_ofs, int chunk_size, void *inode)
{
    lock_acquire (&buffer_cache_op_lock);
    int cache_index = get_buffer_cache_index (sector_idx);

    if (cache_index == CACHE_MISS)
    {
        struct cache_slot* target_cache = cache_slot_alloc ();
        cache_index = target_cache->index;

        block_read (fs_device, sector_idx, target_cache->data);

        target_cache->used = true;
        target_cache->accessed = true;
        target_cache->sector = sector_idx;

        memcpy (buffer + bytes_read, target_cache->data + sector_ofs, chunk_size);
        lock_release (&buffer_cache_lock[cache_index]);

        /* Signaling for read-ahead functionality. */
        if (inode != NULL)
        {
            struct ahead_block* ahead_block = malloc (sizeof (struct ahead_block));
            ahead_block->sector = sector_idx;
            ahead_block->inode = (struct inode *) inode;
            list_push_front (&ahead_list, &ahead_block->elem);
            sema_up (&ahead_list_sema);
        }
    }
    else
    {
        lock_acquire (&buffer_cache_lock[cache_index]);
      
        struct cache_slot* target_cache = &buffer_cache[cache_index];
        target_cache->accessed = true;
        memcpy (buffer + bytes_read, target_cache->data + sector_ofs, chunk_size);

        lock_release (&buffer_cache_lock[cache_index]);
    }
    lock_release (&buffer_cache_op_lock);
 }

/* Write BUFFER starting at BYTES_WRITTEN to cache block for
   SECTOR_IDX with SECTOR_OFS of length CHUNK_SIZE. */
void cache_write(void *buffer , block_sector_t sector_idx, 
                 off_t bytes_written, int sector_ofs, int chunk_size)
{
    lock_acquire (&buffer_cache_op_lock);
    int cache_index = get_buffer_cache_index (sector_idx);

    if (cache_index == CACHE_MISS)
    {
        struct cache_slot* target_cache = cache_slot_alloc ();
        cache_index = target_cache->index;

        
        //printf("sector_idx %d before block read in cache write\n",sector_idx);
        block_read (fs_device, sector_idx, target_cache->data);
        //read ahead?
        target_cache->used = true;
        target_cache->dirty = true;
        target_cache->accessed = true;
        target_cache->sector = sector_idx;
        //printf("sector = %d in cache_write()\n", sector_idx);

        memcpy (target_cache->data + sector_ofs, buffer + bytes_written, chunk_size);

        lock_release (&buffer_cache_lock[cache_index]);
    }
    else
    {
        lock_acquire (&buffer_cache_lock[cache_index]);

        struct cache_slot* target_cache = &buffer_cache[cache_index];

        target_cache->dirty = true;
        target_cache->accessed = true;

        memcpy (target_cache->data + sector_ofs, buffer + bytes_written ,chunk_size);

        lock_release (&buffer_cache_lock[cache_index]);
    }
    lock_release (&buffer_cache_op_lock);
}

/* Flush all cache data into disk.

   This function is called in filesys_done(). */
void cache_flush (void)
{
    for (int i = 0; i < MAX_CACHE_SIZE; i++)
    {
        struct cache_slot* current_slot = &buffer_cache[i];
        if(current_slot->dirty)
        {
            lock_acquire (&buffer_cache_lock[i]);
            block_write (fs_device, current_slot->sector, current_slot->data);
            lock_release (&buffer_cache_lock[i]);
        }
    }
}

/* Thread function for write-behind. */
void write_behind (void)
{
    while (!flag_filesys_done)
    {
        cache_flush ();
        timer_sleep (PERIOD_WRITE_BEHIND);
    }
    
    thread_exit ();
}

/* Thread function for read-ahead. */
void read_ahead (void)
{
    while (!flag_filesys_done)
    {
        sema_down (&ahead_list_sema);

        struct list_elem* e = list_pop_back (&ahead_list);
        struct ahead_block* ahead_block = list_entry (e,struct ahead_block,elem);

        struct inode* inode = (struct inode *)ahead_block->inode;
        block_sector_t current_sector = ahead_block->sector;
        
        int32_t next_sector = get_next_sector (inode, current_sector);

        if (next_sector != -1)
        {
            int cache_index = get_buffer_cache_index (next_sector);

            if(cache_index == CACHE_MISS)
            {
                struct cache_slot* target_cache = cache_slot_alloc ();
                cache_index = target_cache->index;
                
                block_read (fs_device, next_sector, target_cache->data);
                target_cache->used = true;
                target_cache->accessed = true;
                target_cache->dirty = false;
                target_cache->sector = next_sector;
                lock_release (&buffer_cache_lock[cache_index]);
            }
        }

        free (ahead_block);
    }
}