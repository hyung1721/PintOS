#ifndef VM_SWAP_H
#define VM_sWAP_H

#include "devices/block.h"
#include "userprog/process.h"
#include <stdbool.h>
#include "page.h"
#include "frame.h"

extern struct bitmap *swap_table;

void init_swap (void);
void destroy_swap (void);
extern block_sector_t swap_out (void *victim_frame);
extern void swap_in (block_sector_t swap_index, void *frame);
extern struct ft_entry *find_victim (void);

#endif