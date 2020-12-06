#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include <stdbool.h>
#include "off_t.h"

void buffer_cache_init (void);
int get_buffer_cache_index (block_sector_t sector);
void cache_read (void *buffer , block_sector_t sector_idx, 
                 off_t bytes_read, int sector_ofs, int chunk_size, void *inode);
void cache_write (void *buffer , block_sector_t sector_idx, 
                  off_t bytes_written, int sector_ofs, int chunk_size);
void cache_flush (void);

#endif