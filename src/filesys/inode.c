#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define MAX_DIRECT 64
#define MAX_INDIRECT 4

#define SECTOR_MAX_DIRECT MAX_DIRECT
#define SECTOR_MAX_INDIRECT (MAX_DIRECT+128*MAX_INDIRECT)
#define SECTOR_MAX_DOUBLY (MAX_DIRECT+128*MAX_INDIRECT+128*128)

struct lock temp_lock;
struct indirect_block
{
  block_sector_t direct[128];
};

struct doubly_indirect_block
{
  struct indirect_block *indirect[128];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    //block_sector_t start;               /* First data sector. */

    block_sector_t direct[MAX_DIRECT];                /* Direct blocks. */
    struct indirect_block *indirect[MAX_INDIRECT];    /* Indirect blocks. */
    struct doubly_indirect_block *doubly_indirect;    /* Doubly indirect blocks. */

    /* # of direct blocks. */
    uint32_t last_direct;
    /* # of allocated indirect blocks. */
    uint32_t count_allocated_indirect;
    /* # of direct blocks in last indirect block. */
    uint32_t last_indirect;
    /* # of allocated indirect blocks in doubly indirect block. */
    uint32_t count_allocated_doubly_indirect;   
    /* # of direct blocks in last indirect block in doubly indirect block. */
    uint32_t last_doubly_indirect;

    bool is_dir;        

    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[51];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };


bool file_growth(struct inode* inode, off_t size, off_t offset)
{
  //printf("file growth\n");
  bool result = true;
  int max_length = size + offset;
  int total_sector_num = bytes_to_sectors(max_length);
  int current_sector_num = bytes_to_sectors(inode->data.length);
  
  int left = total_sector_num - current_sector_num;

  //printf("total_sector_num %d\n",total_sector_num);

  //printf("current_sector_num %d\n",current_sector_num);

  int direct_num = 0;
  int indirect_num = 0;
  int doubly_indirect_num = 0;
  static char zeros[BLOCK_SECTOR_SIZE];
  memset(zeros,0,BLOCK_SECTOR_SIZE);

  if(current_sector_num < SECTOR_MAX_DIRECT && left > 0 ){
    direct_num =  left <  (SECTOR_MAX_DIRECT - current_sector_num) 
                            ? left 
                            : (SECTOR_MAX_DIRECT- current_sector_num);
    left -= direct_num;
  }

  if(current_sector_num < SECTOR_MAX_INDIRECT && left > 0 ){
    indirect_num = left <  (SECTOR_MAX_INDIRECT - current_sector_num) 
                            ? left 
                            : (SECTOR_MAX_INDIRECT - current_sector_num);
    left -= indirect_num;
  }

  if(current_sector_num < SECTOR_MAX_DOUBLY && left > 0){
    doubly_indirect_num = left < (SECTOR_MAX_DOUBLY  - current_sector_num) 
                            ? left 
                            : (SECTOR_MAX_DOUBLY  - current_sector_num);
  }


  //printf("direct_num %d\n",direct_num);
  //printf("total sector num %d\n",total_sector_num);

  int last_direct = inode->data.last_direct;
  int last_indirect = inode->data.last_indirect; 
  int last_doubly_indirect = inode->data.last_doubly_indirect ; 
  int count_allocated_indirect = inode->data.count_allocated_indirect;


  // direct growth
  for(int i = 0  ; i < direct_num ; i++){
    result = free_map_allocate(1, &inode->data.direct[i + last_direct]);
      if (!result)
        return result;
    block_write (fs_device, inode->data.direct[i + last_direct], zeros);
    //printf("New created sector num : %d direct pos %d\n",inode->data.direct[i + last_direct],i + last_direct);
    
  }
  inode->data.last_direct += direct_num;
  // indirect growth
  if(indirect_num > 0){

    if(last_indirect !=  0){

      int iter = indirect_num < (128 - last_indirect ) ? indirect_num : (128 - last_indirect );

      for(int i = 0 ; i < iter ; i++){
        //printf("last_indirect: %d\n", inode->data.last_indirect);
        result = free_map_allocate(1, &inode->data.indirect[count_allocated_indirect - 1]->direct[i+last_indirect]);
        //printf("direct[63] sector num : %d\n",inode->data.direct[63]);
        //printf("total_sector_num %d\n",total_sector_num);
        //printf("current_sector_num %d\n",current_sector_num);
        if (!result)
          return result;
        block_write (fs_device, inode->data.indirect[count_allocated_indirect - 1]->direct[i+last_indirect], zeros);
        
      }
      indirect_num -= iter;
      inode->data.last_indirect = (inode->data.last_indirect + iter) % 128 ;
    }

    if(indirect_num > 0){

      int count_indirect_iteration = DIV_ROUND_UP(indirect_num,128);
  
      for (int i = 0; i < count_indirect_iteration; i++)
      {
        /* Indirect blocks allocation. */
        inode->data.indirect[count_allocated_indirect + i] = (struct indirect_block *) malloc (sizeof(struct indirect_block));
        
        if (i != (count_indirect_iteration - 1))
        {
          for (int j = 0; j < 128; j++)
          {
            result = free_map_allocate(1, &inode->data.indirect[count_allocated_indirect+ i]->direct[j]);
            if (!result)
              return result;
            block_write (fs_device, inode->data.indirect[count_allocated_indirect+ i]->direct[j],zeros);
          }
          indirect_num -= 128;
        }
        else if (i == count_indirect_iteration - 1)
        {
          int iteration = indirect_num;
         
          for (int j = 0; j < iteration; j++)
          {
            result = free_map_allocate(1, &inode->data.indirect[count_allocated_indirect+ i]->direct[j]);
            //printf("indirect[0][0] sector num : %d\n",inode->data.indirect[0]->direct[0]);
            if (!result)
              return result;
            block_write (fs_device, inode->data.indirect[count_allocated_indirect+ i]->direct[j],zeros);
          }

          inode->data.last_indirect = indirect_num == 128 ? 0: indirect_num;
          inode->data.count_allocated_indirect += count_indirect_iteration;
    
        }      
      }
    }
  }

  // doubly_indirect growth
  if(doubly_indirect_num > 0){


    int count_allocated_doubly_indirect = inode->data.count_allocated_doubly_indirect;

    if(count_allocated_doubly_indirect == 0){
      inode->data.doubly_indirect = (struct doubly_indirect_block *) malloc (sizeof (struct doubly_indirect_block));
    }

    if(last_doubly_indirect !=  0){

      int iter = doubly_indirect_num < (128 - last_doubly_indirect ) 
                                    ? doubly_indirect_num 
                                    : (128 - last_doubly_indirect );

      for(int i = 0 ; i < iter ; i++){
        result = free_map_allocate(1, &inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect - 1]->direct[i+last_doubly_indirect]);
        if (!result)
          return result;
        block_write (fs_device, inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect - 1]->direct[i+last_doubly_indirect] ,zeros);
      }
      doubly_indirect_num -= iter;
      inode->data.last_doubly_indirect = (inode->data.last_doubly_indirect + iter) % 128 ;
    }

    if(doubly_indirect_num > 0){

      int count_doubly_indirect_iteration = DIV_ROUND_UP(doubly_indirect_num,128);
  
      for (int i = 0; i < count_doubly_indirect_iteration; i++)
      {
        /* Indirect blocks allocation. */
        inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect + i] = (struct indirect_block *) malloc (sizeof(struct indirect_block));

        if (i != (count_doubly_indirect_iteration - 1))
        {
          for (int j = 0; j < 128; j++)
          {
            result = free_map_allocate(1, &inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect+ i]->direct[j]);
            if (!result)
              return result;
            block_write (fs_device,inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect+ i]->direct[j],zeros);
          }
          doubly_indirect_num -= 128;
        }
        else if (i == count_doubly_indirect_iteration - 1)
        {
          int iteration = doubly_indirect_num; 
        
          for (int j = 0; j < iteration; j++)
          {
            result = free_map_allocate(1, &inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect+ i]->direct[j]);
            if (!result)
              return result;
            block_write (fs_device,inode->data.doubly_indirect->indirect[count_allocated_doubly_indirect+ i]->direct[j],zeros);
          }

          inode->data.last_doubly_indirect = doubly_indirect_num == 128 ? 0: doubly_indirect_num;
          inode->data.count_allocated_doubly_indirect += count_doubly_indirect_iteration;
    
        }      
      }
    }

  }
  inode->data.length = max_length;
  
  cache_write (&inode->data, inode->sector, 0, 0, BLOCK_SECTOR_SIZE);
  return result;
}

/* Allocate indexed inode. 

   For supporting a file of at most 8MB size, we allocate inode
   with indexing by constructing direct blocks, indirect blocks,
   and doubly indirect blocks. Indirect blocks and doubly indirect
   block structures are allocated in physical memory, not disk to
   reduce waste of disk for storing these blocks.*/
bool
inode_allocate (size_t sectors, struct inode_disk *disk_inode)
{
  bool result = false;

  //printf ("length: %d in allocate", disk_inode->length);

  if (sectors == 0)
    return true;

  size_t temp = sectors;
  size_t remain_indirect_sector = 0;
  size_t remain_doubly_indirect_sector = 0;
  int count_direct_iteration = 0;
  int count_indirect_iteration = 0;
  int count_doubly_indirect_iteration = 0;



  /* Count direct blocks. */
  count_direct_iteration = sectors < MAX_DIRECT ? sectors : MAX_DIRECT;
  disk_inode->last_direct = count_direct_iteration;
  temp -= count_direct_iteration;
  
  if (temp > 0)
  {
    count_indirect_iteration = temp < MAX_INDIRECT * 128 ? DIV_ROUND_UP (temp, 128) : MAX_INDIRECT;
    temp -= 128 * (count_indirect_iteration - 1);
    
    if (temp < 128)
    {
      remain_indirect_sector = temp;
      temp -= remain_indirect_sector;
    }
    else
      temp -= 128;

    if (temp > 0)
    {
      count_doubly_indirect_iteration = temp < (128 * 128) ? DIV_ROUND_UP (temp, 128) : -1;
      if (count_doubly_indirect_iteration == -1)
        return false;
      temp -= 128 * (count_doubly_indirect_iteration - 1);
      remain_doubly_indirect_sector = temp;
    }
  }

  if (count_direct_iteration > 0)
  {
    for (int i = 0; i < count_direct_iteration; i++)
    {
      result = free_map_allocate(1, &disk_inode->direct[i]);
      if (!result)
        break;
    }
  }
  
  if (count_indirect_iteration > 0)
  {
    disk_inode->count_allocated_indirect = count_indirect_iteration;

    for (int i = 0; i < count_indirect_iteration; i++)
    {
      /* Indirect blocks allocation. */
      disk_inode->indirect[i] = (struct indirect_block *) malloc (sizeof(struct indirect_block));

      if (i != (count_indirect_iteration - 1))
      {
        for (int j = 0; j < 128; j++)
        {
          result = free_map_allocate(1, &disk_inode->indirect[i]->direct[j]);
          if (!result)
            break;
        }
      }
      else if (i == count_indirect_iteration - 1)
      {
        int iteration = remain_indirect_sector == 0 ? 128 : remain_indirect_sector;
        disk_inode->last_indirect = remain_indirect_sector;

        for (int j = 0; j < iteration; j++)
        {
          result = free_map_allocate(1, &disk_inode->indirect[i]->direct[j]);
          if (!result)
            break;
        }
      }      
    }
  }
  
  if (count_doubly_indirect_iteration > 0)
  {
    disk_inode->count_allocated_doubly_indirect = count_doubly_indirect_iteration;
    
    /* Doubly indirect block allocation. */
    disk_inode->doubly_indirect = (struct doubly_indirect_block *) malloc (sizeof (struct doubly_indirect_block));

    for (int i = 0; i < count_doubly_indirect_iteration; i++)
    {
      /* doubly_indirect->indirect allocation. */
      disk_inode->doubly_indirect->indirect[i] = (struct indirect_block *) malloc (sizeof(struct indirect_block));

      if (i != (count_doubly_indirect_iteration - 1))
      {
        for (int j = 0; j < 128; j++)
        {
          result = free_map_allocate(1, &disk_inode->doubly_indirect->indirect[i]->direct[j]);
          if (!result)
            break;
        }
      }
      else if (i == count_doubly_indirect_iteration - 1)
      {
        int iteration = remain_doubly_indirect_sector == 0 ? 128 : remain_doubly_indirect_sector;
        disk_inode->last_doubly_indirect = remain_doubly_indirect_sector;

        for (int j = 0; j < iteration; j++)
        {
          result = free_map_allocate(1, &disk_inode->doubly_indirect->indirect[i]->direct[j]);
          if (!result)
            break;
        }
      }
    }
  }

  //printf("count_direct_iteration %d \n",count_direct_iteration);
  //printf("direct[0] = %d in inode_allocate()\n", disk_inode->direct[0]);
  // printf("count_indirect_iteration %d \n",count_indirect_iteration);
  // printf("count_doubly_indirect_iteration %d \n",count_doubly_indirect_iteration);

  // printf("remain_indirect_sector %d\n",remain_indirect_sector);
  // printf("remain_doubly_indirect_sector %d\n",remain_doubly_indirect_sector);
  
  return result;
}

/* Release indexed inode.
   
   Free all the used map in direct blocks, indirect blocks, and
   doubly indirect blocks. This function must deallocate indirect
   blocks and doubly indirect block allocated with malloc(). */
void
inode_release (struct inode_disk *disk_inode)
{
  int i, j;
  
  /* Free direct blocks. */
  for (i = 0; i < disk_inode->last_direct; i++)
  {
    free_map_release (disk_inode->direct[i], 1);
  }

  /* Free indirect blocks. */
  for (i = 0; i < disk_inode->count_allocated_indirect; i++)
  {
    if (i != (disk_inode->count_allocated_indirect - 1))
    {
      for (j = 0; j < 128; j++)
        free_map_release (disk_inode->indirect[i]->direct[j], 1);
    }
    else
    {
      for (j = 0; j < disk_inode->last_indirect; j++)
        free_map_release (disk_inode->indirect[i]->direct[j], 1);
    }

    free (disk_inode->indirect[i]);
  }

  /* Free doubly indirect blocks. */
  for (i = 0; i < disk_inode->count_allocated_doubly_indirect; i++)
  {
    if (i != (disk_inode->count_allocated_doubly_indirect - 1))
    {
      for (j = 0; j < 128; j++)
        free_map_release (disk_inode->doubly_indirect->indirect[i]->direct[j], 1);
      
      free (disk_inode->doubly_indirect->indirect[i]);
    }
    else
    {
      for (j = 0; j < disk_inode->last_doubly_indirect; j++)
        free_map_release (disk_inode->doubly_indirect->indirect[i]->direct[j], 1);
      
      free (disk_inode->doubly_indirect->indirect[i]);
      free (disk_inode->doubly_indirect);
    }
  }
}

/* Write all inode for disk data into disk. */
void
inode_disk_write_all (char *zeros, struct inode_disk *disk_inode)
{
  for (int i = 0; i < disk_inode->last_direct; i++)
    block_write (fs_device, disk_inode->direct[i], zeros);

  for (int i = 0; i < disk_inode->count_allocated_indirect; i++)
  {
    if (i != (disk_inode->count_allocated_indirect - 1))  
      for (int j = 0; j < 128; j++)
        block_write (fs_device, disk_inode->indirect[i]->direct[j], zeros);
    else
      for (int j = 0; j < disk_inode->last_indirect; j++)
        block_write (fs_device, disk_inode->indirect[i]->direct[j], zeros);
  }

  for (int i = 0; i < disk_inode->count_allocated_doubly_indirect; i++)
  {
    if (i != (disk_inode->count_allocated_doubly_indirect - 1))
      for (int j = 0; j < 128; j++)
        block_write (fs_device, disk_inode->doubly_indirect->indirect[i]->direct[j], zeros);
    else
      for (int j = 0; j < disk_inode->last_doubly_indirect; j++)
        block_write (fs_device, disk_inode->doubly_indirect->indirect[i]->direct[j], zeros);
  }
}

int32_t
get_next_sector (struct inode* inode, block_sector_t current_sector)
{
  int last_direct = inode->data.last_direct;
  int last_indirect = inode->data.last_indirect;
  int last_doubly_indirect = inode->data.last_doubly_indirect;
  int count_allocated_indirect = inode->data.count_allocated_indirect;
  int count_allocated_doubly_indirect = inode->data.count_allocated_doubly_indirect;
  int i, j;

  /* Find current_sector from direct blocks. */
  for (i = 0; i < last_direct; i++)
  {
    if (inode->data.direct[i] == current_sector)
    {
      if (i != (last_direct - 1))
        return inode->data.direct[i + 1];
      else
      {
        if (last_direct != MAX_DIRECT)
          return -1;
        else
        {
          if (count_allocated_indirect != 0)
            return inode->data.indirect[0]->direct[0];
          else
            return -1;
        }
      }
      
    }
  }

  /* Find current_sector from indirect blocks. */
  for (i = 0; i < count_allocated_indirect; i++)
  {
    if (i != count_allocated_indirect - 1)
    {
      for (j = 0; j < 128; j++)
      {
        if (inode->data.indirect[i]->direct[j] == current_sector)
        {
          if (j != 127)
            return inode->data.indirect[i]->direct[j + 1];
          else
            return inode->data.indirect[i + 1]->direct[0];
        }
      }
    }
    else
    {
      if (last_indirect != 0)
      {
        for (j = 0; j < last_indirect; j++)
        {
          if (inode->data.indirect[i]->direct[j] == current_sector)
          {
            if (j != (last_indirect - 1))
              return inode->data.indirect[i]->direct[j + 1];
            else
              return -1;
          }
        }
      }
      else
      {
        for (j = 0; j < 128; j++)
        {
          if (inode->data.indirect[i]->direct[j] == current_sector)
          {
            if (j != 127)
              return inode->data.indirect[i]->direct[j + 1];
            else if (count_allocated_indirect < 4)
              return -1;
            else if (count_allocated_indirect == 4)
            {
              if (count_allocated_doubly_indirect != 0)
                return inode->data.doubly_indirect->indirect[0]->direct[0];
              else
                return -1;
            }
          }
        }
      }
    }
  }

  /* Find current_sector from doubly indirect blocks. */
  for (i = 0; i < count_allocated_doubly_indirect; i++)
  {
    if (i != count_allocated_doubly_indirect - 1)
    {
      for (j = 0; j < 128; j++)
      {
        if (inode->data.doubly_indirect->indirect[i]->direct[j] == current_sector)
        {
          if (j != 127)
            return inode->data.doubly_indirect->indirect[i]->direct[j + 1];
          else
            return inode->data.doubly_indirect->indirect[i + 1]->direct[0];
        }
      }
    }
    else
    {
      int iter = last_doubly_indirect == 0 ? 128 : last_doubly_indirect;

      for (j = 0; j < iter; j++)
      {
        if (inode->data.doubly_indirect->indirect[i]->direct[j] == current_sector)
        {
          if (j != (iter - 1))
            return inode->data.doubly_indirect->indirect[i]->direct[j + 1];
          else
            return -1;
        }
      }
    }
  }

  return -1;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  /* The original version of byte_to_sector() doesn't work.
     Hence, we modify this function so that it return sector
     number which is appropriate for our implementation of
     indexed inode, not sequential block sector number. */

  block_sector_t result;
  
  if (pos >= inode->data.length)
  { 
    //printf("pos: %d length: %d\n", pos, inode->data.length);
    return -1;
  }

  uint32_t sector_pos = pos / BLOCK_SECTOR_SIZE;
  
  if (sector_pos < MAX_DIRECT){
      //printf("direct sector pos\n",sector_pos);
     result = inode->data.direct[sector_pos];
  }
   
  else if (sector_pos < (MAX_DIRECT + MAX_INDIRECT * 128))
  {
    uint32_t indirect_pos = (sector_pos - MAX_DIRECT) / 128;
    uint32_t direct_pos = (sector_pos - MAX_DIRECT) % 128;
    result = inode->data.indirect[indirect_pos]->direct[direct_pos];
    //printf("indirect[%d]->direct[%d] = %d\n",indirect_pos, direct_pos, result);
    
  }
  else if (sector_pos < (MAX_DIRECT + MAX_INDIRECT * 128 + 128 * 128))
  {
    uint32_t doubly_indirect_pos = (sector_pos - ((MAX_DIRECT + MAX_INDIRECT * 128))) / 128;
    uint32_t direct_pos = (sector_pos - ((MAX_DIRECT + MAX_INDIRECT * 128))) % 128;
    result = inode->data.doubly_indirect->indirect[doubly_indirect_pos]->direct[direct_pos];
  }
  else
    result = -1;

  return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init(&temp_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->is_dir = is_dir;
      disk_inode->magic = INODE_MAGIC;

      if (inode_allocate (sectors, disk_inode))
      {
        cache_write (disk_inode, sector, 0, 0, BLOCK_SECTOR_SIZE);

        if (sectors > 0)
        {
          static char zeros[BLOCK_SECTOR_SIZE];
          
          inode_disk_write_all (zeros, disk_inode);
        }
        success = true;
      }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (&inode->data, inode->sector, 0, 0, BLOCK_SECTOR_SIZE,inode);
  //printf("inode->sector: %d in open()\n", inode->sector);
  //printf("inode->data.length: %d in open()\n", inode->data.length);
  //block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{

  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          inode_release (&inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  //uint8_t *bounce = NULL;
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      //printf("inode sector: %d in read_at()\n", inode->sector);
      //printf("offset : %d, ", offset);
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      //printf("sector index: %d in read_at()\n", sector_idx);

      // passed EOF
      if(sector_idx == -1){
            break;
      } 
    
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      //   {
      //     /* Read full sector directly into caller's buffer. */
      //     //block_read (fs_device, sector_idx, buffer + bytes_read);
      //     cache_read(buffer, sector_idx, bytes_read, 0, BLOCK_SECTOR_SIZE);
      //   }
      // else 
      //   {
      //     /* Read sector into bounce buffer, then partially copy
      //        into caller's buffer. */
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (BLOCK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }
      //     //block_read (fs_device, sector_idx, bounce);

      //     cache_read(bounce, sector_idx, 0, 0, BLOCK_SECTOR_SIZE);
      //     memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      //     //cache_read(buffer, sector_idx, bytes_read, sector_ofs, chunk_size);
      //   }
      cache_read(buffer, sector_idx, bytes_read, sector_ofs, chunk_size,inode);
      
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  //free(bounce);

  return bytes_read;
}



/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  bool result;

  if (inode->deny_write_cnt)
    return 0;


  if(size+ offset > inode->data.length ){
    result = file_growth(inode, size, offset);
     if(!result) ASSERT(0); //handling??
    //printf("FILE GROWTH size : %d  offset : %d length : %d\n",size,offset, inode->data.length);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      //printf("offset: %d in \n", offset);
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      
      //printf("sector index: %d, offset: %d in write_at()\n", sector_idx, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write(buffer, sector_idx, bytes_written, sector_ofs, chunk_size);

      // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
      //   {
      //     /* Write full sector directly to disk. */
      //     //block_write (fs_device, sector_idx, buffer + bytes_written);

      //     cache_write(buffer, sector_idx, bytes_written, 0, chunk_size);
      //   }
      // else 
      //   {
      //     /* We need a bounce buffer. */
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (BLOCK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }

      //     /* If the sector contains data before or after the chunk
      //        we're writing, then we need to read in the sector
      //        first.  Otherwise we start with a sector of all zeros. */
      //     if (sector_ofs > 0 || chunk_size < sector_left) 
      //       //block_read (fs_device, sector_idx, bounce);
      //       cache_read(bounce, sector_idx, 0, 0, BLOCK_SECTOR_SIZE);
      //     else
      //       memset (bounce, 0, BLOCK_SECTOR_SIZE);
      //     memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
      //     //block_write (fs_device, sector_idx, bounce);

      //     cache_write(bounce, sector_idx, 0, 0, BLOCK_SECTOR_SIZE);
      //   }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  //printf("check\n");
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_is_dir (struct inode *inode)
{
  return inode->data.is_dir;
}

bool
inode_is_removed (struct inode *inode)
{
  return inode->removed;
}