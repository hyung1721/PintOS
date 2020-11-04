#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"

#define STACK_HEURISTIC 32
#define MAX_PAGE_STACK 2048

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Own functions for project #2 */

/* Prototype declaration */
void push_arguments(int argc, char **argv, void **esp);

/* Function definition */

/* Push arguments specified by argc and argv into stack, which is 
   pointed by esp. This function works like following steps.
   
   For example command, '/bin/ls -l foo bar',
   push_arguments() pushes arguments in the following order.
   
   1. Push 'bar\0', 'foo\0', '-l\0', and '/bin/ls\0'.
   2. Push word_align.
   3. Push zero for argv[4]
   4. Push the address of 'bar\0' in stack.
   5. Push the address of 'foo' in stack.
   6. Push the address of '-l\0' in stack.
   7. Push the address of '/bin/ls\0' in stack.
   8. Push the address of argv[0] in stack, which represents argv.
   9. Push the return address, which is zero.

   The order of pushing arguments is based on 80x86 calling
   convention in Pintos manual. */
void
push_arguments(int argc, char **argv, void **esp)
{
  int i, current_len, total_len = 0;
  
  for (i = (argc - 1); i >= 0; i--)
  {
    current_len = strlen(argv[i]);
    total_len += (current_len + 1);

    /* Decrease esp by (length of current argument + 1)
       where +1 is needed for including '\0' at the end of argument */
    *esp -= (current_len + 1);
    strlcpy(*esp, argv[i], current_len + 1);

    /* Replace i-th element of argv with argument's address
       in stack. This address will be pushed in stack again. */
    argv[i] = *esp;
  }

  /* Word-aligned bytes */
  int diff = 4 - (total_len % 4);
  *esp -= diff;

  for (i = argc; i >= 0; i--)
  {
    *esp -= 4;
    **(uint32_t **)esp = argv[i];
  }

  /* Push pointer to argv[0] in stack */
  *esp -= 4;
  **(uint32_t **)esp = *esp + 4; 

  /* Push  argument count in stack. */
  *esp -= 4;
  **(uint32_t **)esp = (uint32_t)argc;

  /* Push return address, 0, in stack. */
  *esp -= 4;
  **(uint32_t **)esp = 0;

  // hex_dump(*esp, *esp, PHYS_BASE-(*esp), true);

  free(argv);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread *current_thread = thread_current ();
  struct thread *new_thread;

  //printf("file name : %s\n", file_name);
  // char *thread_name, *save_ptr;

  // thread_name = strtok_r (file_name, " ", &save_ptr);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  else
  {
    /* If creation succeed, this thread should be child of current thread. */
    new_thread = get_thread_with_pid(tid);
    list_push_back (&current_thread->children, &new_thread->elem_child);
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  char temp_file_name[128];
  struct intr_frame if_;
  bool success;

  char *token, *save_ptr;
  int argc = 0;
  char **argv;
  int i;
  
  strlcpy (temp_file_name, file_name, strlen (file_name) + 1);

  /* Count the number of argument passed by aux (= file_name_). */
  for (token = strtok_r (temp_file_name, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
  {
    argc++;
  }

  /* Store each arguments into argv by using strtok_r(). */
  argv = (char **)malloc(sizeof(char *) * (argc + 1) );
  
  strlcpy (temp_file_name, file_name, strlen (file_name) + 1);

  for (i = 0, token = strtok_r (temp_file_name, " ", &save_ptr);
       i < argc;
       i++, token = strtok_r (NULL, " ", &save_ptr))
  {
    argv[i] = token;
  }

  /* This is for zero bytes in stack, which wiil be used in
     push_arguments(). */
  argv[argc] = 0;


  /* For project #3 */
  init_spt (&thread_current()->spt);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (argv[0], &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
  {
    thread_current ()->failed = true;
    thread_exit ();
  }
  else
  {
    /* Do pushing arguments into stack. */
    thread_current ()->loaded = true;
    push_arguments(argc, argv, &if_.esp);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *current_thread = thread_current ();
  struct list *children = &current_thread->children;
  struct list_elem *e;
  struct thread *t;
  int ret;

  for (e = list_begin (children); e != list_end (children); e = list_next (e))
  {
    t = list_entry (e, struct thread, elem_child);
    
    if (t->tid == child_tid)
    {
      /* Wait until child process is successfully loaded. */
      sema_down (&t->exit_sema);
      list_remove (&t->elem_child);

      /* Retrieve child process's exit status. */
      ret = t->status_exit;

      /* Signal to child that deleting would be fine. */
      sema_up (&t->delete_sema);

      return ret;
    }
  }

  /* There is no such child. */
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  
  free_frame_entry(cur);
  
  destroy_spt(&cur->spt);
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Signal to parent that child can exit. */
  sema_up (&cur->exit_sema);
  /* Wait until parent remove child from parent's children and 
     retrieve child's exit status. */
  sema_down (&cur->delete_sema);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;
      //printf("%dth iteration\n", i);
      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  //printf("here?\n");
  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
  
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  struct spt_entry *created_spte;

  //printf("load segment begin with writable : %d upage : %p\n", writable, upage);
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      //printf("page read bytes : %d\n", page_read_bytes);
      

      created_spte = create_spte_from_exec(file, ofs, upage, 
                                            page_read_bytes, page_zero_bytes, writable);
      
      if (created_spte == NULL)
         return false;
      
      
      /* Get a page of memory. */
      uint8_t *kpage = frame_alloc (PAL_USER, created_spte);
      //printf("upage : %p kpage: %p | ", upage, kpage);
      
      if (kpage == NULL)
      {
        //printf("here4\n");
        free (created_spte);
      }

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        { 
          //printf("C\n");
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          //printf("B\n");
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  //printf("load segment end\n");
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage, *upage;
  bool success = false;

  upage = ((uint8_t *) PHYS_BASE) - PGSIZE;

  struct spt_entry *new_entry = create_spte_from_stack (upage);
  kpage = frame_alloc (PAL_USER | PAL_ZERO, new_entry);

  if (kpage != NULL) 
    {
      success = install_page (upage, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;
      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Load page from swap disk by using supplemental page table
   entry. First, allocate frame and install a mapping between
   upage and frame. And, call swap_in() fuction to load a page
   from swap disk. */
bool
load_from_swap (struct spt_entry *spte)
{
  ASSERT (spte != NULL);
  
  uint8_t *frame = frame_alloc (PAL_USER, spte);
  
  //printf("frame %p\n", frame);
  //printf("Frame allocate done\n");
  if (!frame)
      return false;

  if (!install_page (spte->upage, frame, spte->writable))
  {
      //frame_free(frame);
      return false;
  }
  
  //printf("install page done\n");
  spte->paddr = frame;
  //printf("SWAP_IN - swap_index: %d upage: %p frame: %p\n",spte->swap_index, spte->upage,frame);
  swap_in (spte->swap_index, spte->paddr);
  //printf("swap in done\n");
  spte->state = MEMORY;

  return true;
}

/* Grow an user stack. This function is only called when
   kernel detect page fault with STACK_HEURISTIC. It checks
   how many pages would be needed for growing stack and
   containing fault_addr into that stack. */
bool
stack_growth (uint8_t *fault_addr)
{
  ASSERT (fault_addr != NULL);

  bool result;

  uint8_t *ptr, *upage, *kpage;
  int old_cnt, new_cnt;
  
  old_cnt = thread_current ()->growth_cnt;

  /* calculate growth count. */
  new_cnt = calculate_growth_count (PHYS_BASE, fault_addr);

  /* Update its growth_cnt for later stack growth. */
  thread_current ()->growth_cnt = new_cnt;

  /* Impose the limit of stack size. */
  if (new_cnt > MAX_PAGE_STACK)
    return false;
    
  /* Allocate page and install mapping. */
  for (int i = old_cnt + 1; i <= new_cnt; i++)
  {
    upage = PHYS_BASE - PGSIZE * i;
    
    struct spt_entry *new_entry = create_spte_from_stack (upage);
    kpage = frame_alloc (PAL_USER | PAL_ZERO, new_entry);
    result = install_page (upage, kpage, true);
  }
  if(result == false) printf("FALSE\n");
  return result;
}

/* Calculate how many pages are needed for growing from start
   to end. In our implementation, start will become PHYS_BASE
   and end will becoma a fault_addr.*/
int
calculate_growth_count (uint8_t *start, uint8_t *end)
{
  int i;
  uint8_t *temp = start;
  
  for (i = 0; temp > end; i++)
  {
    temp -= PGSIZE;
  }

  return i;
}