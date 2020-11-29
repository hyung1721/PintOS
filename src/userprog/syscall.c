#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "hash.h"
#include "lib/round.h"
typedef int pid_t;
static void syscall_handler (struct intr_frame *);
/* For Project #2. USER PROGRAM */

/* Prototype Declaration */

void check_invalid_pointer(uint32_t *, const void *);

/* The functions listed below are system call handler functions.
   They have same format with the original system call. */
void syscall_halt (void);
void syscall_exit (int);
pid_t syscall_exec (const char *);
int syscall_wait (pid_t);
bool syscall_create (const char *, unsigned);
bool syscall_remove (const char *);
int syscall_open (const char *);
int syscall_filesize (int);
int syscall_read (int, void *, unsigned);
int syscall_write (int, const void *, unsigned);
void syscall_seek (int, unsigned);
unsigned syscall_tell (int);
void syscall_close (int);
mapid_t syscall_mmap (int, void *);
void syscall_munmap (mapid_t);

void check_child_before_exit(struct thread *);

struct lock syscall_lock;

void
syscall_init (void) 
{
  lock_init (&syscall_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Interrupt frame f has several data. By examining data pointed by
     esp, call appropriate system call function we implemented. */

  uint32_t syscall_num = *(uint32_t *)(f->esp);

  /* To avoid invalid pointer from user program, we should check invalid
     pointer from the stack. Especially, some system calls which take
     pointer arguments must check a validity of them. 
     
     By calling check_invalid_pointer(), syscall_handler examines
     the validity of a pointer. For specific infomation about this 
     function, please refer to the comments above the definition of
     check_invalid_pointer() function. */

  /* If the system call function have a return value, by setting f->eax
     which is %eax register for return value, syscall_handler passes the
     return value to the kernel. */
  
  switch (syscall_num)
    {
      case SYS_HALT:
        syscall_halt ();
        break;
      case SYS_EXIT:
        check_invalid_pointer (thread_current ()->pagedir,
                              (int *)(f->esp + 4));
        syscall_exit (*(int *)(f->esp + 4));
        /* returning status to kernel -> what? */
        break;
      case SYS_EXEC:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(const void **)(f->esp + 4));
        f->eax = syscall_exec (*(const char **)(f->esp + 4));
        break;
      case SYS_WAIT:
        f->eax = syscall_wait (*(pid_t *)(f->esp + 4));
        break;
      case SYS_CREATE:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(const char **)(f->esp + 4));
        f->eax = syscall_create (*(const char **)(f->esp + 4),
                                *(int *)(f->esp + 8));
        break;
      case SYS_REMOVE:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(const char **)(f->esp + 4));
        f->eax = syscall_remove (*(const char **)(f->esp + 4));
        break;
      case SYS_OPEN:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(const char **)(f->esp + 4));
        f->eax = syscall_open (*(const char **)(f->esp + 4));
        break;
      case SYS_FILESIZE:
        f->eax = syscall_filesize (*(int *)(f->esp + 4));
        break;
      case SYS_READ:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(void **)(f->esp + 8));
        f->eax = syscall_read (*(int *)(f->esp + 4),
                              *(void **)(f->esp + 8),
                              *(unsigned *)(f->esp + 12));
        break;
      case SYS_WRITE:
        check_invalid_pointer (thread_current ()->pagedir,
                               *(const void **)(f->esp + 8));
        f->eax = syscall_write (*(int *)(f->esp + 4),
                                *(const void **)(f->esp + 8),
                                *(unsigned *)(f->esp + 12));
        break;
      case SYS_SEEK:
        syscall_seek(*(int *)(f->esp + 4),
                     *(unsigned *)(f->esp + 8));
        break;
      case SYS_TELL:
        f->eax = syscall_tell (*(int *)(f->esp + 4));
        break;
      case SYS_CLOSE:
        syscall_close (*(int *)(f->esp + 4));
        break;
      case SYS_MMAP:
      //이 경우만 특별히
        f->eax = syscall_mmap (*(int *)(f->esp + 4), *(const void **)(f->esp + 8));
        break;
      case SYS_MUNMAP:
        syscall_munmap (*(mapid_t *)(f->esp + 4));
        break;
      default:
        printf ("SYSCALL NUM %d is not yet implemented!\n", syscall_num);
        break;
    }

    
}

void
check_invalid_pointer(uint32_t *pd, const void *ptr)
{
  
  if(get_spte(ptr)) return;

  if (ptr == NULL
      || is_kernel_vaddr (ptr)
      || pagedir_get_page (pd, ptr) == NULL)
    syscall_exit (-1);
}

/* System call handler function for halt() system call. 
   
   Terminates Pintos by calling shutdown_power_off(). */
void
syscall_halt (void)
{
  shutdown_power_off ();
}

/* System call handler function for exit() system call. 
   
   Terminates current user program. */
void
syscall_exit (int status)
{
  char thread_name[128];
  char *token, *save_ptr;
  struct thread *cur = thread_current ();
  struct file **fd_table = cur->fd_table;
  size_t len = strlen (cur->name);
  strlcpy (thread_name, cur->name, len + 1);

  token = strtok_r (thread_name, " ", &save_ptr);

  /* For parent to retrieve child's exit status, child store
     its exit status. */
  cur->status_exit = status;

  /* Close all opened files of this process to avoid memory leaks. */
  for (int i = 2; i < FD_MAX_SIZE; i++)
  {
    if (fd_table[i] != NULL)
      syscall_close(i);
  }

  for (int i = 2; i < FD_MAX_SIZE; i++)
  {
    if (cur->mmap_table[i] != NULL)
      syscall_munmap (i);
  }

  check_child_before_exit(cur);

  /* Process termination message with status. */
  printf ("%s: exit(%d)\n", token, status);

  thread_exit ();
 
}

/* System call handler function for exec() system call. 
   
   Runs the executable whose name is given in cmd_line, passing
   any arguments, and returns the new process's pid. 
   
   This function creates a new process as a child of current 
   process and waits for successfully loading of child. */
pid_t
syscall_exec (const char *cmd_line)
{
  lock_acquire(&syscall_lock);
  /* Passing cmd_line, create a new process. */
  pid_t pid = process_execute (cmd_line);
  
  
  if (pid == -1){
    lock_release(&syscall_lock);
    return pid;
    
  }
    
  struct thread *current_thread = thread_current ();
  struct thread *child_process = get_thread_with_pid (pid);

  /* The parent must wait for loading of child process. 
     
     loaded variable means that child's load() is done.
     failed variable means that child's load() is failed. */
  sema_down (&child_process->load_sema);
  if (child_process->failed)
  {
    lock_release(&syscall_lock);
    list_remove (&child_process->elem_child);
    sema_up (&child_process->delete_sema);
    
    return -1;
  }
  
  lock_release(&syscall_lock);
  return pid;
}

/* System call handler function for wait() system call. 
   
   Waits for a child process pid and retrieves the child's
   eixt status. */
int
syscall_wait (pid_t pid)
{
  int wait_result = process_wait (pid);
  return wait_result;
}

/* System call handler function for create() system call. 
   
   Creates a new file called filename, initially_size bytes in size */
bool
syscall_create (const char *filename, unsigned initial_size)
{
  lock_acquire (&syscall_lock);
  bool result = filesys_create (filename, initial_size);
  lock_release (&syscall_lock);
  return result;
}

/* System call handler function for remove() system call. 
   
   Deletes the file called filename. */
bool
syscall_remove (const char *filename)
{
  lock_acquire (&syscall_lock);
  bool result = filesys_remove (filename);
  lock_release (&syscall_lock);
  return result;
}

/* System call handler function for open() system call. 
   
   Opnes the file called filename. */
int
syscall_open(const char* filename)
{
  lock_acquire(&syscall_lock);
  /* Missing filename must be avoided. */
  if (!strcmp (filename, "")){
     lock_release(&syscall_lock);
     return -1;
  }
  
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table;
  struct file *opened_file;
  char *token, *save_ptr;
  int new_fd = -1, i = 0;

  opened_file = filesys_open (filename);
  
  /* If filesys_open() fails, return -1. */
  if (opened_file == NULL){
    lock_release (&syscall_lock);
    return -1;
  }

  /* Need to implement generally in process_execute() */
  token = strtok_r (current_thread->name, " ", &save_ptr);

  /* This file is executable, so must be denied for writing. */
  if (!strcmp (filename, token))
    file_deny_write (opened_file);

  /* Update current process's file descriptor table. */
  for (i = 2 ; i < FD_MAX_SIZE; i++)
  {
    if (fd_table[i] == NULL)
    {
      new_fd = i;
      fd_table[i] = opened_file;
      break;
    } 
  }

  if (i == FD_MAX_SIZE)
    file_close (opened_file);

  lock_release(&syscall_lock);
  return new_fd;
}

/* System call handler function for filesize() system call. 
   
   Returns the size, in bytes, of the file open as fd. */
int
syscall_filesize (int fd)
{
  lock_acquire (&syscall_lock);
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table ; 
 
  /* Check the validity of the fd. */
  if (fd < 2 || fd >= FD_MAX_SIZE)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }
    
  if (fd_table[fd] == NULL)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }

  lock_release (&syscall_lock);
  return (int)file_length (fd_table[fd]);
}

/* System call handler function for read() system call. 
   
   Reads size bytes from the file open as fd into buffer. */
int
syscall_read (int fd, void *buffer, unsigned size)
{
  /* Check if the buffer is located in read-only section. */
  void *upage = pg_round_down(buffer);
  struct spt_entry *spte = get_spte (upage);
  if (!spte->writable)
    syscall_exit (-1);

  lock_acquire (&syscall_lock);
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table;

  /* For STDIN */
  if (fd == 0)
  { 
    for(int i = 0 ; i < size ; i++)
    {
      char c; 
      if ((c = input_getc()) == 0) return i;

      *(char*)buffer = c;
      buffer++;
    }
    lock_release (&syscall_lock);
    return size;
  }
  
  /* Check the validity of the fd. */
  if (fd < 0 || fd == 1 || fd >= FD_MAX_SIZE)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }
  else if (fd_table[fd] == NULL)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }

  pin_page (buffer, size);
  int result = file_read (fd_table[fd], buffer, size);
  lock_release (&syscall_lock);
  unpin_page (buffer, size);

  return result;
}
/* System call handler function for wrtie() system call. 
   
   Writes size bytes from buffer to the open file fd. */
int
syscall_write (int fd, const void *buffer, unsigned size)
{
  lock_acquire (&syscall_lock);
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table;

  /* For STDOUT */
  if (fd == 1)
  {
    putbuf (buffer, size);
    lock_release (&syscall_lock);
    return size;
  }
  
  /* Check the validity of the fd. */
  if (fd < 1 || fd >= FD_MAX_SIZE)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1); 
  }
  else if (fd_table[fd] == NULL)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }
  /* Check if this file is writable. */
  if (get_deny_write (fd_table[fd]))
  {
    lock_release (&syscall_lock);
    return 0;
  }
  lock_release (&syscall_lock);
  pin_page (buffer, size);
  int result = file_write (fd_table[fd], buffer,size);
  unpin_page (buffer, size);
  return result;
}

/* System call handler function for seek() system call. 
   
   Changes the next bytes to be read or written in opne file
   fd to position. */
void
syscall_seek (int fd, unsigned position)
{
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table ; 

  /* Check the validity of the fd. */
  if (fd < 2 || fd >= FD_MAX_SIZE)
    syscall_exit (-1);
  if (fd_table[fd] == NULL)
    syscall_exit (-1);
  
  lock_acquire(&syscall_lock);
  file_seek (fd_table[fd], position);
  lock_release(&syscall_lock);
}

/* System call handler function for tell() system call. 
   
   Returns the position of the next bytes to be read or written
   in open file fd. */
unsigned
syscall_tell (int fd)
{
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table ; 

  /* Check the validity of the fd. */
  if (fd < 2 || fd >= FD_MAX_SIZE)
    syscall_exit (-1);
  if (fd_table[fd] == NULL)
    syscall_exit (-1);

  lock_acquire (&syscall_lock);
  unsigned result = (unsigned)file_tell (fd_table[fd]);
  lock_release (&syscall_lock);
  return result;
}
/* System call handler function for close() system call. 
   
   Closes file descriptor fd. */
void
syscall_close (int fd)
{
  struct thread *current_thread = thread_current ();
  struct file **fd_table = current_thread->fd_table;

  /* Check the validity of the fd. */
  if (fd < 2 || fd >= FD_MAX_SIZE)
    syscall_exit (-1);

  if (fd_table[fd] == NULL)
    syscall_exit (-1);
  
  lock_acquire (&syscall_lock);
  file_close(fd_table[fd]);
  /* After closing fd, fd_table must be updated. */
  fd_table[fd] = NULL;
  lock_release (&syscall_lock);
}

/* System call handler function for mmap() system call.

   Maps the file open as fd into the process's virtual 
   address space. */
mapid_t
syscall_mmap (int fd, void *addr)
{
  lock_acquire (&syscall_lock);
  
  struct thread *cur = thread_current ();
  struct file *file = cur->fd_table[fd];
  off_t file_len;

  if (file == NULL
     || pg_ofs (addr) != 0
     || (file_len = file_length (file)) == 0
     || addr == (void*)0
     || is_kernel_vaddr (addr) 
     || fd == 0
     || fd == 1)
  {
    lock_release (&syscall_lock);
    return -1;
  }

  uint32_t read_bytes, zero_bytes;
  read_bytes = file_len;
  zero_bytes = (ROUND_UP (file_len, PGSIZE) - read_bytes);
  off_t offset = 0;

  /* Because file would be closed after mmap(), we use file_reopen()
     to access file data further accessing. This new_file will be
     used to create supplemental page table entry for addr. */
  struct file* new_file = file_reopen(file);
  
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Detect overlapping with other segment. */
      if (get_spte(addr) != NULL)
      {
        lock_release (&syscall_lock);
        return -1;
      }
      
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
     
      struct spt_entry *created_spte;
      created_spte = create_spte_from_mmap (new_file, offset, addr, 
                                            page_read_bytes, 
                                            page_zero_bytes, true);
      
      if (created_spte == NULL)
      {
        lock_release (&syscall_lock);
        return false;
      }

      /* Advance. */
      offset += PGSIZE;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      addr += PGSIZE;
    }

  cur->mmap_table[fd] = new_file;
  lock_release (&syscall_lock);
  return fd;
}

/* System call handler function for munmap() system call. 

   Unmaps the mapping designated by mapping. */
void
syscall_munmap (mapid_t mapping)
{
  lock_acquire (&syscall_lock);
  struct thread *cur = thread_current ();
  int fd = mapping;
  struct file* file = cur->mmap_table[fd];
 
  /* Unmmaping unmapped mapping will be denied. */
  if(cur->mmap_table[fd] == NULL)
  {
    lock_release (&syscall_lock);
    syscall_exit (-1);
  }

  struct hash spt = cur->spt;
  struct hash_iterator i;

  hash_first (&i, &spt);

  while (hash_next (&i))
  {
      struct spt_entry *entry = hash_entry (hash_cur (&i),
                                            struct spt_entry,
                                            elem);
      if(entry->file == file)
      {       
        if(entry->state == MEMORY 
           && pagedir_is_dirty (cur->pagedir,entry->upage))
        {
          lock_acquire (&filesys_lock);
          file_write_at (entry->file, entry->paddr,
                         entry->read_bytes,
                         entry->offset);
          lock_release (&filesys_lock);
        }
        else if(entry->state == SWAP_DISK 
                && pagedir_is_dirty (cur->pagedir,entry->upage))
        {
          int swap_index = entry->swap_index;

          uint8_t* temp_buffer = (uint8_t *)malloc (sizeof(uint8_t)*PGSIZE);
          swap_in (swap_index,temp_buffer);

          lock_acquire (&filesys_lock);
          file_write_at (entry->file, temp_buffer, 
                         entry->read_bytes, 
                         entry->offset);
          lock_release (&filesys_lock);
          
          free (temp_buffer);
        }

        cur->mmap_table[fd] = NULL;
        // hash_delete(&spt, hash_cur (&i));
      }
  }
  file_close(file);
  lock_release (&syscall_lock);
} 

/* Check if there are children which does not exit yet.
   And do sema_up(&delete_sema) for those child because 
   they may wait delete_sema to be up in process_exit().*/
void
check_child_before_exit (struct thread *t)
{
  struct list *children = &t->children;
  struct list_elem *e;
  struct thread *child;

  for (e = list_begin (children); e != list_end (children); e = list_next (e))
  {
    child = list_entry (e, struct thread, elem_child);
    sema_up (&child->delete_sema);
  }
}