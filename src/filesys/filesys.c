#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;
bool flag_filesys_done;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  flag_filesys_done = false;
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  thread_current ()->current_dir = dir_open_root ();

  free_map_open ();

  lock_init(&filesys_lock);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_flush ();
  flag_filesys_done = true;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  char file_name[15];
  struct dir *dir = parsing_file_name (name, file_name);

  //printf("filesys create filename: %s\n",file_name);
  //printf("%s is added to sector num %d\n",file_name, inode_get_inumber(dir_get_inode(dir)));
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  if (success && is_dir)
  {
  
    struct dir *new_dir = dir_open (inode_open (inode_sector));
    //printf("mkdir %s sector num %d\n",file_name,inode_get_inumber(dir_get_inode(new_dir)) );
    if (new_dir != NULL)
    {
      if (!dir_add (new_dir, ".", inode_sector))
        return false;
      if (!dir_add (new_dir, "..", inode_get_inumber (dir_get_inode (dir))))
        return false;
    }

    dir_close (new_dir);
  }
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char file_name[15];
  struct dir *dir = parsing_file_name(name, file_name);
  struct inode *inode = NULL;


  //printf("sector num %d\n",inode_get_inumber(dir_get_inode(dir)));

  //root dir
  if(!strcmp(name,"/")){

    inode = dir_get_inode(dir);
    struct file* file = file_open(inode);
    dir_close (dir);
    return file;
  }

  if (dir != NULL){
    dir_lookup (dir, file_name, &inode);

    // if( strcmp(name,".") && strcmp(name,".."))
    //   dir_close (dir);
    // else{
    //   free(dir);
    // }
  }
  


  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char file_name[15];
  struct dir *dir = parsing_file_name (name, file_name);
  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
