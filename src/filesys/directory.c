#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  /* Modified for creation of root directory.
  
     . and .. for root directory must represent root directory itself.*/

  bool result = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  
  if (sector == ROOT_DIR_SECTOR)
  {
    struct dir *new_dir = dir_open (inode_open (sector));

    if (new_dir != NULL)
    {
      if (!dir_add (new_dir, ".", sector))
        return result;
      if (!dir_add (new_dir, "..", sector))
        return result;
    }

    dir_close (new_dir);
  }

  return result;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);

  /* If inode does not represent directory, it cannot be
     opened. */
  if (inode != NULL && dir != NULL && inode_is_dir (inode))
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e){
    //printf("e.name %s\n",e.name);
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  } 
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
  {
    //printf("sector num : %d in dir_lookup()\n", e.inode_sector);
    *inode = inode_open (e.inode_sector);
  }
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;


  if(inode_is_dir(inode)){
    off_t ofs_;
    struct dir_entry e_;
    for (ofs_ = 0; inode_read_at (inode, &e_, sizeof e_, ofs_) == sizeof e_;
          ofs_ += sizeof e_){
      if(!strcmp(e_.name , ".") || !strcmp(e_.name , "..")) continue;
    
      if (e_.in_use){
        return false;   
      }  
    } 

    // for (ofs_ = 0; inode_read_at (inode, &e_, sizeof e_, ofs_) == sizeof e_;
    //       ofs_ += sizeof e_){
    //   if(!strcmp(e_.name , ".") || !strcmp(e_.name , "..")){
    //      e_.in_use = false;
    //      inode_write_at (inode, &e_, sizeof e_, ofs_);
    //   }
    // } 

  }  
  
  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
   
      if(!strcmp(e.name , ".")||!strcmp(e.name , "..")) continue;
      
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

/* Returns the directory given by path_name and do the process 
   of parsing file name given by pull path.

   This function parses the path_name with respect to '/' and
   store last file name in the path_name into file_name. */
struct dir *
parsing_file_name (const char *path_name, char *file_name)
{
  size_t length = strlen (path_name), count;
  char temp_path_name[length + 1];
  char parsed_file_name[length][15];

  strlcpy (temp_path_name, path_name, length + 1);
  temp_path_name[length] = '\0';

  bool absolute_path = (temp_path_name[0] == '/') ? true : false;

  char *token, *save_ptr;

  for (token = strtok_r (temp_path_name, "/", &save_ptr), count = 0;
       token != NULL;
       token = strtok_r (NULL, "/", &save_ptr), count++)
  {
    int token_length = strlen (token);
    if (token_length > 14)
      return NULL;
    strlcpy (parsed_file_name[count], token, token_length + 1);
    parsed_file_name[count][token_length] = '\0';
  }
 
  size_t len = strlen (parsed_file_name[count - 1]);
  strlcpy (file_name, parsed_file_name[count - 1], len + 1);
  file_name[len] = '\0';

  struct dir *temp_dir;

  if (absolute_path)
    temp_dir = dir_open_root ();
  else{
    //printf("thread number %d\n",thread_current ()->tid);
    //printf("current dir sector num: %d in parsing()\n", inode_get_inumber (dir_get_inode (thread_current ()->current_dir)));
    temp_dir = dir_reopen (thread_current ()->current_dir);
    //printf("temp_dir sector num: %d in parsing()\n", inode_get_inumber (dir_get_inode (temp_dir)));
  }

  for (int i = 0; i < count; i++)
  {
    struct inode *temp_inode = NULL;
    if (i != (count - 1))
    {
      if (dir_lookup (temp_dir, parsed_file_name[i], &temp_inode))
      {
        dir_close (temp_dir);
        temp_dir = dir_open (temp_inode);
        if (temp_dir == NULL)
          return NULL;
      }
      else
        return NULL;
    }
    else{
      if(inode_is_removed(dir_get_inode(temp_dir))){
        return NULL;
      } 
      else return temp_dir;
    }
  }
}
