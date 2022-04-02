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
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
CHILD* new_child(void);
void pcb_init(struct thread*, struct process*, CHILD*);
CHILD* find_child(pid_t);
void decrement_ref_cnt(CHILD*);
void decrement_children_ref_cnt(struct process*);
void pcb_exit_setup(struct process*);
void free_spa(SPA*);
bool setup_thread(void (**eip)(void), void** esp, struct sfun_args* sa);

/* helpers */
static bool setup_thread_stack(void ** esp);
void drop_all_holding_locks(void);
void free_upage(void);
void wakeup_waiting_thread(void);
void remove_cur_from_thread_list(void);
void join_all_nonmain_threads(void);
void remove_died_thread_list(struct process*);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  pcb_init(t, t->pcb, NULL);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

CHILD* new_child() {
  CHILD* cptr = (CHILD*) palloc_get_page(0);
  if (cptr == NULL) {
    return NULL;
  }
  sema_init(&cptr->exec_sema, 0);
  sema_init(&cptr->wait_sema, 0);
  cptr-> exit_status = ERROR;
  cptr->is_exited = false;
  cptr->is_waiting = false;
  cptr->ref_cnt = 2;
  lock_init(&cptr->ref_lock);
  return cptr;
}

void free_spa(SPA* spaptr) {
  palloc_free_page(spaptr->file_name);
  palloc_free_page(spaptr->new_c);
  palloc_free_page(spaptr);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  SPA* spaptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  spaptr = (SPA*) palloc_get_page(0);
  if (spaptr == NULL)
    return TID_ERROR;
  spaptr->file_name = palloc_get_page(0);
  spaptr->new_c = new_child();
  if (spaptr->file_name == NULL || spaptr->new_c == NULL) {
    return TID_ERROR;
  }
  strlcpy(spaptr->file_name, file_name, PGSIZE - sizeof(spaptr->new_c));
  
  char* file_name_cpy = (char*) malloc(sizeof(char) * (strlen(file_name) + 1));
  char* cpy_base = file_name_cpy;
  strlcpy(file_name_cpy, file_name, strlen(file_name) + 1);
  char** saveptr = &file_name_cpy;
  char* prog_name = strtok_r(file_name_cpy, " ", saveptr);


  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(prog_name, PRI_DEFAULT, start_process, spaptr);
  sema_down(&spaptr->new_c->exec_sema);
  free(cpy_base);
  struct process* pcb = thread_current()->pcb;
  list_push_front(&pcb->children, &spaptr->new_c->elem);
  if (tid == TID_ERROR) {
    free_spa(spaptr);
  }
  else {
    if (spaptr->new_c->is_exited && spaptr->new_c->exit_status == ERROR) {
      tid = -1;
    }
    palloc_free_page(spaptr);
  }
  return tid;
}

void pcb_init(struct thread* t, struct process *new_pcb, CHILD *new_c) {
  new_pcb->pagedir = NULL;
  t->pcb = new_pcb;
  t->pcb->main_thread = t;
  strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  list_init(&t->pcb->children);
  t->pcb->curr_as_child = new_c;
  if (new_c) {
    new_c->pid = get_pid(new_pcb);
  }
  /* Initialize fd related structure member */
  t->pcb->cur_fd = 2;
  list_init(&t->pcb->file_descriptor_table);

  /* project 2 task 3 */
  list_init(&t->pcb->thread_list);
  list_init(&t->pcb->died_thread_list);
  t->pcb->num_locks = 0;
  t->pcb->num_semas = 0;
  lock_init(&t->pcb->process_lock);
  t->pcb->highest_upage = NULL;
  t->pcb->is_exiting = false;
  t->pcb->is_main_exiting = false;
  new_pcb->main_thread = t;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* spaptr_) {
  SPA* spaptr = (SPA*) spaptr_;
  char* file_name = spaptr->file_name;
  CHILD* new_c = spaptr->new_c;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    pcb_init(t, new_pcb, new_c);
  }
 
  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* Save current FPU registers values to local variable,
     initialize it again for new thread/process and store it in *sf,
     and restore the current ones */
    int local_var[27];
    asm volatile("FSAVE (%0)" : : "g"(&local_var) : "memory");
    asm volatile("FNINIT" : : : "memory");
    asm volatile("FSAVE (%0)" : : "g"(&if_.fpu) : "memory");
    asm volatile("FRSTOR (%0)" : : "g"(&local_var) : "memory");

    success = load(file_name, &if_.eip, &if_.esp);
  }
  
  if(success) {
    struct file* file = filesys_open(t->pcb->process_name);
    t->pcb->curr_executable = file;
    file_deny_write(file);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    new_c->exit_status = ERROR;
    pcb_exit_setup(pcb_to_free);
    t->pcb = NULL;
    free(pcb_to_free);
  }
  sema_up(&new_c->exec_sema);

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(spaptr->file_name);
  if (!success) {
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

CHILD* find_child(pid_t pid) {
  struct list *children = &thread_current()->pcb->children;
  CHILD* cptr;
  for (struct list_elem *e = list_begin(children); e != list_end(children);
      e = list_next(e)) {
    cptr = list_entry(e, CHILD, elem);
    if (cptr->pid == pid) {
      return cptr;
    }
  }
  return NULL;
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  CHILD* child_to_wait = find_child(child_pid);
  if (child_to_wait == NULL || child_to_wait->is_waiting) {
    return ERROR;
  }
  child_to_wait->is_waiting = true;
  sema_down(&child_to_wait->wait_sema);
  if (child_to_wait->is_exited) {
    return child_to_wait->exit_status;
  }
  return ERROR;
}

void decrement_ref_cnt(CHILD* cptr) {
  lock_acquire(&cptr->ref_lock);
  cptr->ref_cnt--;
  if (cptr->ref_cnt == 0) {
    palloc_free_page(cptr);
    return;
  }
  else {
    lock_release(&cptr->ref_lock);
    return;
  }
}

void decrement_children_ref_cnt(struct process* pcb) {
  struct list_elem *e = list_begin(&pcb->children);
  struct list_elem *next_e;
  CHILD* cptr;
  while (e != list_end(&pcb->children)) {
    next_e = list_next(e);
    cptr = list_entry(e, CHILD, elem);
    decrement_ref_cnt(cptr);
    e = next_e;
  }
}

void remove_died_thread_list(struct process* pcb) {
  struct list_elem *e = list_begin(&pcb->died_thread_list);
  while (!list_empty(&pcb->died_thread_list)) {
    e = list_pop_front(&pcb->died_thread_list);
    free(list_entry(e, struct died_thread, elem));
  }
  return;
}

void pcb_exit_setup(struct process* pcb_to_free) {
  pcb_to_free->curr_as_child->is_exited = true;
  remove_died_thread_list(pcb_to_free);
  decrement_children_ref_cnt(pcb_to_free);
  decrement_ref_cnt(pcb_to_free->curr_as_child);
  sema_up(&pcb_to_free->curr_as_child->wait_sema);
}

struct file_descriptor* find_file_des(int fd) {
  struct process* pcb = thread_current()->pcb;
  struct list_elem *e;
  for (e = list_begin(&(pcb->file_descriptor_table)); e != list_end(&(pcb->file_descriptor_table)); e = list_next(e)) {
    struct file_descriptor* descriptor = list_entry(e, struct file_descriptor, elem);
    if (descriptor->fd == fd) {
      return descriptor;
    }
  }
  return NULL;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  uint32_t* pd;
  /* project 2 task 3 */
  if (cur_pcb != NULL) {
    lock_acquire(&cur_pcb->process_lock);
    if (!is_main_thread(cur, cur_pcb)) {
      // cur is not main thread
      cur_pcb->is_exiting = true;
      lock_release(&cur_pcb->process_lock);
      pthread_exit();
    }
    // if cur is main thread
    if (!cur_pcb->is_main_exiting) {
      // the main thread is the first time enter process_exit, call pthread_exit_main()
      cur_pcb->is_exiting = true;
      cur_pcb->is_main_exiting = true;
      lock_release(&cur_pcb->process_lock);
      pthread_exit_main();
    }
  }
  // cur_pcb is NULL or the second time main thread enters process_exit()

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  file_close(cur->pcb->curr_executable);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;

  /* Close all the file descriptors */
  struct list_elem *cur_file = list_begin(&pcb_to_free->file_descriptor_table);
  while (cur_file != list_end(&pcb_to_free->file_descriptor_table)) {
    struct file_descriptor* descriptor = list_entry(cur_file, struct file_descriptor, elem);
    cur_file = list_next(cur_file);
    file_close(descriptor->file);
    free(descriptor);
  }

  printf("%s: exit(%d)\n", pcb_to_free->process_name, pcb_to_free->curr_as_child->exit_status);

  cur->pcb = NULL;
  pcb_exit_setup(pcb_to_free);
  free(pcb_to_free);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

int count_args(const char*);
void push_stack(void**, void*, size_t);
void args_load(const char*, void**);
void args_split(char*, char**);

int count_args(const char* file_name) {
  int count = 0;
  for (int i = 1; file_name[i] != '\0'; i++) {
    if (file_name[i] == ' ' && file_name[i - 1] != ' ' && file_name[i + 1] != '\0') {
      count++;
    }
  }
  return count + 1;
}

void push_stack(void** esp, void* src, size_t size) {
  *esp -= size;
  memcpy(*esp, src, size);
  return;
}

void args_split(char* file_name, char* argv[]) {
  char** saveptr = &file_name;
  char* arg = strtok_r(file_name, " ", saveptr);
  for(int i = 0; arg != (char*) NULL; i++) {
    argv[i] = arg;
    arg = strtok_r((char*) NULL, " ", saveptr);
  }
  return;
}

void args_load(const char* file_name, void** esp) {
  char* file_name_cpy = (char*) malloc(sizeof(char) * (strlen(file_name) + 1));
  int nArgs = count_args(file_name);
  char** args = (char**) malloc(sizeof(char*) * nArgs);
  unsigned int allByteCount = sizeof(char*) * (nArgs + 1) + sizeof(char**) + sizeof(int);
  strlcpy(file_name_cpy, file_name, strlen(file_name) + 1);
  // get all arguments in file_name_cpy
  args_split(file_name_cpy, args);
  // push all arguments onto user stack, record the location of each arg on the stack
  // accumulate the used bytes on stack
  int argByteCount = 0;
  char** argsAddrInStack = (char**) malloc(sizeof(char*) * nArgs + 1);
  char* arg;
  for (int argIndex = nArgs - 1; argIndex >= 0; argIndex--) {
    arg = args[argIndex];
    argByteCount = sizeof(char) * (strlen(arg) + 1);
    allByteCount += argByteCount;
    push_stack(esp, arg, argByteCount);
    argsAddrInStack[argIndex] = (char*) *esp;
  }
  // push stack-aglin onto user stack
  argByteCount = sizeof(uint8_t) * ((0b10000 - (allByteCount & 0b1111)) & 0b1111);
  uint8_t *arg_zeros = calloc(argByteCount / sizeof(uint8_t), sizeof(uint8_t));
  push_stack(esp, arg_zeros, sizeof(uint8_t) * argByteCount);
  free(arg_zeros);
  // push NULL ptr after stack-aglin by convention
  char* null_ptr = (char*) NULL;
  push_stack(esp, &null_ptr, sizeof(char*));
  // push all pointers to argument onto the user stack
  push_stack(esp, argsAddrInStack, sizeof(char*) * nArgs);
  // push argv onto stack
  char** argv_0 = *esp;
  push_stack(esp, &argv_0, sizeof(char**));
  // push argc
  push_stack(esp, &nArgs, sizeof(int));
  free(args);
  free(argsAddrInStack);
  free(file_name_cpy);
  return;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();


  /* Open executable file. */
  file = filesys_open(t->pcb->process_name);

  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  
  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
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
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

  args_load(file_name, esp);
  *esp -= sizeof(void*); // fake return address

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
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
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Helper */
static bool setup_thread_stack(void ** esp) {
  uint8_t* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    bool success = false;
    int i = 0;
    while (!success) {
      i += 1;
      success = install_page(((uint8_t*)PHYS_BASE) - i * PGSIZE, kpage, true);
    }
    thread_current()->upage = ((uint8_t*)PHYS_BASE) - i * PGSIZE;
    *esp = PHYS_BASE - (i - 1) * PGSIZE;
    return true;
  }
  return false;
}

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void), void** esp, struct sfun_args *sa) {
  // Activate page directory
  process_activate();

  if (setup_thread_stack(esp)) {
    //push pthread_fun and void* arg
    unsigned int allByteCount = sizeof(pthread_fun) + sizeof(void *);
    unsigned int argByteCount = sizeof(uint8_t) * ((0b10000 - (allByteCount & 0b1111)) & 0b1111);
    uint8_t* arg_zeros = calloc(argByteCount / sizeof(uint8_t), sizeof(uint8_t));
    push_stack(esp, arg_zeros, sizeof(uint8_t) * argByteCount);
    free(arg_zeros);
    // no need to add NULL ptr after stack-algin
    push_stack(esp, &sa->arg, sizeof(void*));
    push_stack(esp, &sa->tfun, sizeof(pthread_fun));
    //set eip to stub_fun
    *eip = (void (*)(void)) sa->sfun;
    return true;
  }
  return false;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) {
  struct sfun_args sa;
  tid_t tid;

  struct thread* t = thread_current();
  sa.sfun = sf;
  sa.tfun = tf;
  sa.arg = arg;
  sa.pcb = t->pcb;
  sema_init(&sa.exec_sema, 0);

  //TODO: Add a lock to guarantee that only one function can run this at a time
  lock_acquire(&t->pcb->process_lock);
  tid = thread_create("", PRI_DEFAULT, start_pthread, &sa);
  lock_release(&t->pcb->process_lock);
  if (tid == TID_ERROR) {
    return tid;
  }
  sema_down(&sa.exec_sema);
  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {
  struct sfun_args* exec = (struct sfun_args*)exec_;
  struct intr_frame if_;
  bool success;
  
  struct thread *t = thread_current();
  t->pcb = exec->pcb;
  list_push_back(&exec->pcb->thread_list, &t->proc_elem);

  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  int local_var[27];
  asm volatile("FSAVE (%0)" : : "g"(&local_var) : "memory");
  asm volatile("FNINIT" : : : "memory");
  asm volatile("FSAVE (%0)" : : "g"(&if_.fpu) : "memory");
  asm volatile("FRSTOR (%0)" : : "g"(&local_var) : "memory");

  success = setup_thread(&if_.eip, &if_.esp, exec);
  if_.esp -= 4;

  sema_up(&exec->exec_sema);

  if (!success) {
    thread_exit();
  }

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}


/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  if (cur->tid == tid) {
    return TID_ERROR;
  }
  for (struct list_elem* e = list_begin(&cur_pcb->died_thread_list); e != list_end(&cur_pcb->died_thread_list); e = list_next(e)) {
    struct died_thread *dt_ptr = list_entry(e, struct died_thread, elem);
    if (dt_ptr->tid == tid) {
      return dt_ptr->is_joined ? TID_ERROR : tid;
    }
  }
  struct thread* waiting_thread = NULL;
  if (cur_pcb->main_thread->tid == tid) {
    if (cur_pcb->is_main_exiting) {
      cur->join_sema_ptr = &cur_pcb->main_thread->join_sema;
      return tid;
    }
    waiting_thread = cur_pcb->main_thread;
  }
  else {
    for (struct list_elem* e = list_begin(&cur_pcb->thread_list); e != list_end(&cur_pcb->thread_list); e = list_next(e)) {
      struct thread *t = list_entry(e, struct thread, proc_elem);
      if (t->tid == tid) {
        waiting_thread = t;
        break;
      }
    }
  }
  if (waiting_thread != NULL && waiting_thread->status == THREAD_DYING) {
    return tid;
  }
  if (waiting_thread == NULL || waiting_thread->join_sema_ptr != NULL) {
    return TID_ERROR;
  }
  waiting_thread->join_sema_ptr = &cur->join_sema;  // can use thread_block?
  sema_down(&cur->join_sema);
}

/* Free all current thread's holding locks */
void drop_all_holding_locks() {
  struct thread* cur = thread_current();
  for (struct list_elem *e = list_begin(&cur->holding_locks); e != list_end(&cur->holding_locks); e = list_next(e)) {
    struct lock *l = list_entry(e, struct lock, elem);
    lock_release(l);
  }
}

void free_upage() {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  lock_acquire(&cur_pcb->process_lock);
  pagedir_clear_page(cur_pcb->pagedir, cur->upage);
  lock_release(&cur_pcb->process_lock);
}

void wakeup_waiting_thread() {
  struct thread* cur = thread_current();
  if (cur->join_sema_ptr != NULL) {
    sema_up(cur->join_sema_ptr);
  }
}

void remove_cur_from_thread_list() {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  struct died_thread* dt_ptr = (struct died_thread*) malloc(sizeof(struct died_thread));
  dt_ptr->tid = cur->tid;
  dt_ptr->is_joined = cur->join_sema_ptr != NULL;
  lock_acquire(&cur_pcb->process_lock);
  list_remove(&cur->proc_elem);
  list_push_back(&cur_pcb->died_thread_list, &dt_ptr->elem);
  lock_release(&cur_pcb->process_lock);
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  // redirect main thread to pthread_exit_main()
  if (is_main_thread(cur, cur_pcb)) {
    pthread_exit_main();
  }
  free_upage();
  wakeup_waiting_thread();
  drop_all_holding_locks();
  remove_cur_from_thread_list();
  thread_exit();
}

void join_all_nonmain_threads() {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  struct thread* to_join = NULL;
  lock_acquire(&cur_pcb->process_lock);
  while (!list_empty(&cur_pcb->thread_list)) {
    to_join = list_entry(list_begin(&cur_pcb->thread_list), struct thread, proc_elem);
    lock_release(&cur_pcb->process_lock);
    pthread_join(to_join->tid);
    lock_acquire(&cur_pcb->process_lock);
  }
  lock_release(&cur_pcb->process_lock);
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* cur = thread_current();
  struct process* cur_pcb = cur->pcb;
  // redirect all non main threads to pthread_exit()
  if (!is_main_thread(cur, cur->pcb)) {
    pthread_exit();
  }
  lock_acquire(&cur_pcb->process_lock);
  cur_pcb->is_main_exiting = true;
  lock_release(&cur_pcb->process_lock);
  wakeup_waiting_thread();
  drop_all_holding_locks();
  join_all_nonmain_threads();
  // if no other threads call process_exit(), set exit status to 0 (no error)
  if (!cur_pcb->is_exiting) {
    cur_pcb->is_exiting = true;
    cur_pcb->is_main_exiting = true;
    cur_pcb->curr_as_child->exit_status = 0;
  }
  // all non-main threads are exited, exit the process
  // the exit status is set by thread that calls syscall exit 
  // the exit status is -1 if no thread call syscall exit
  process_exit();
}
