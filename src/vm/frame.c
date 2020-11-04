#include "frame.h"

struct list frame_table;
struct lock frame_table_lock;

void
init_frame_table (void)
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);
}

// destroy_frame_table(); test case할때는 frame table이 있어야 하니까 
// 이 함수는 없어도 괜찮지 않을까

struct list_elem*
remove_ft_entry (struct ft_entry *fte)
{
    struct list_elem* e;
    palloc_free_page (fte->frame);
    e = list_remove(&fte->elem);
    free(fte);
    return e;
    
}

struct ft_entry *
create_fte (void *frame, struct spt_entry *spte)
{
    struct ft_entry *fte = malloc (sizeof (struct ft_entry));
    fte->frame = frame;
    fte->spte = spte;
    fte->t = thread_current ();

    list_push_front (&frame_table, &fte->elem);
}

void *
frame_alloc (enum palloc_flags flags, struct spt_entry *spte)
{
    if ((flags & PAL_USER) == 0)
        return NULL;
    
    void *frame = palloc_get_page (flags);
    // printf("****** %d\n",*(uint8_t *)0xc0294000);
    
    if (!frame)
    {
        lock_acquire (&frame_table_lock);
       
        struct ft_entry *fte = find_victim ();

        lock_release (&frame_table_lock);

        frame = fte->frame;
        block_sector_t swap_index = swap_out (frame);
        //printf("SWAP_OUT - swap_index: %d upage: %p frame: %p\n", swap_index, fte->spte->upage,frame);
        
        // swap_out된 frame의 spte, pte 업데이트
        
        update_spte (fte->spte, SWAP_DISK, swap_index);
     
        remove_ft_entry (fte);

        frame = palloc_get_page (flags);
        
        create_fte (frame, spte);
        //printf("create fte done\n");
    }
    else{
        
        create_fte (frame, spte);
    }
        

    return frame;
}


void free_frame_entry(struct thread* cur){

    struct list_elem *e;
    e = list_begin (&frame_table);
    while(e != list_end (&frame_table))
    {
      struct ft_entry* temp_entry = list_entry (e, struct ft_entry, elem);
      
      if( cur == temp_entry->t )
        {
          pagedir_clear_page (cur->pagedir,
                                temp_entry->spte->upage);
          e = remove_ft_entry(temp_entry);
        }
      else
          e = list_next (e);
    }


}