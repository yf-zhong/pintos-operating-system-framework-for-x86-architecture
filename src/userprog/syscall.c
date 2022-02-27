#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame*);

bool is_valid_char_ptr(const char*);
void sys_practice(struct intr_frame*, int);
void sys_halt(void);
void sys_exec(struct intr_frame*, const char*);
void sys_wait(struct intr_frame*, pid_t);
void sys_exit(struct intr_frame*, int);

bool is_valid_char_ptr(const char* c) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  while (is_user_vaddr(c) && pagedir_get_page(pd, c)) {
    if (*c == '\0') {
      return true;
    }
    c++;
  }
  return false;
}

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock); /* Init the lock for file syscall */
}

void sys_practice(struct intr_frame* f, int i) {
  f->eax = i + 1;
  return;
}

void sys_halt() {
  shutdown_power_off();
}

void sys_exec(struct intr_frame* f, const char* cmd_line) {
  // check if cmd_line valid
  if (is_valid_char_ptr(cmd_line)) {
    f->eax = process_execute(cmd_line);
  }
  else {
    sys_exit(f, -1);
  }
  return;
}

void sys_wait(struct intr_frame* f, pid_t pid) {
  f->eax = process_wait(pid);
  return;
}

void sys_exit(struct intr_frame* f, int status) {
    f->eax = status;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
    struct process* pcb = thread_current()->pcb;
    pcb->curr_as_child->exit_status = status;
    process_exit();
}

void sys_create(struct intr_frame* f, const char* file, unsigned initial_size) {  
  /* Todo: Argument validation */

  /* Get current user program pcb */
  bool flag;
  /* Lock required */
  lock_acquire(&file_sys_lock);
  flag = filesys_create(file, initial_size);
  /* Lock release required */
  lock_release(&file_sys_lock);
  f->eax = flag;
  return;
}

// void sys_remove(struct intr_frame* f, const char* file) {return;}

// void sys_open(struct intr_frame* f, const char* file) {return;}

// void sys_filesize(struct intr_frame* f, int fd) {return;}

// void sys_read(struct intr_frame* f, int fd, void* buffer, unsigned size) {return;}

void sys_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
  } else if (fd == 2 || fd == 0) {
    /* TODO: May need revise */
    f->eax = -1;
  } else {
    int bytes_read;
    struct process* pcb = thread_current()->pcb;
    lock_acquire(&file_sys_lock);
    struct list_elem *e;
    for (e = list_begin(&(pcb->file_descriptor_table)); e != list_end(&(pcb->file_descriptor_table)); e = list_next(e)) {
      struct file_descriptor *descriptor = list_entry(e, struct file_descriptor, elem);
      if (descriptor->fd == fd) {
        bytes_read = file_write(descriptor->file, buffer, size);
        f->eax = bytes_read;
        lock_release(&file_sys_lock);
        return;
      }
    }
    f->eax = -2;
    lock_release(&file_sys_lock);
  }
  return;
}

// void sys_seek(struct intr_frame* f, int fd, unsigned position) {return;}

// void sys_tell(struct intr_frame* f, int fd) {return;}

// void sys_close(struct intr_frame* f, int fd) {return;}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  switch(args[0]) {
    case SYS_PRACTICE:
      if ((sizeof(int) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_practice(f, args[1]);
      break;
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_WAIT:
      if ((sizeof(pid_t) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_wait(f, args[1]);
      break;
    case SYS_EXEC:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_exec(f, (char*) args[1]);
      break;
    case SYS_EXIT:
      if ((sizeof(int) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_exit(f, args[1]);
      break;
    /* File operations */
    case SYS_CREATE:
      sys_create(f, (const char*) args[1], args[2]);  /* Working On */
      break;
    case SYS_REMOVE:
    //   sys_remove(f, args[1]);  /* Pending */
    //   use filesys_remove(const char *name)
      break;
    case SYS_OPEN:
    //   sys_open(f, args[1]);    /* Pending */
    //   use filesys_open(const char *name)
      break;
    case SYS_FILESIZE:
    //   sys_filesize(f, args[1]);/* Pending */
    //   use file_length(struct file*)
      break;
    case SYS_READ:
    //   sys_read(f, args[1]);    /* Pending */
    //   use file_read(struct file*, void *, off_t)
      break;
    case SYS_WRITE:
      sys_write(f, args[1], (const void*) args[2], args[3]);   /* Revision needed */
    //   use file_write()
      break;
    case SYS_SEEK:
    //   sys_seek(f, args[1]);    /* Pending */
      break;
    case SYS_TELL:
    //   sys_tell(f, args[1]);    /* Pending */
      break;
    case SYS_CLOSE:
    //   sys_close(f, args[1]);   /* Pending */
      break;
    default:
      f->eax = -3; /* If the NUMBER is not defined */
  }
}

/* Iterate through file descriptor table to find fd. */
struct file* to_file_ptr(int fd) {
  struct process* pcb = thread_current()->pcb;
  struct list_elem *e;
  for (e = list_begin(&(pcb->file_descriptor_table)); e != list_end(&(pcb->file_descriptor_table)); e = list_next(e)) {
    struct file_descriptor *descriptor = list_entry(e, struct file_descriptor, elem);
    if (descriptor->fd == fd) {
      return descriptor->file;
    }
  }
  return NULL;
}