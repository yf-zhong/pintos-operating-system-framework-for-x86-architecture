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
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame*);

bool is_valid_char_ptr(const char*);
void sys_practice(struct intr_frame*, int);
void sys_halt(void);
void sys_exec(struct intr_frame*, const char*);
void sys_wait(struct intr_frame*, pid_t);
void sys_exit(struct intr_frame*, int);

bool file_create(struct intr_frame*, const char*, unsigned);
bool file_remove(struct intr_frame*, const char*);
int file_open(struct intr_frame*, const char*);
int file_filesize(struct intr_frame*, int);
int file_read(struct intr_frame*, int, void*, unsigned);
int file_write(struct intr_frame*, int, const void*, unsigned);
void file_seek(struct intr_frame*, int, unsigned);
unsigned file_tell(struct intr_frame*, int);
void file_close(struct intr_frame*, int);

bool is_valid_char_ptr(const char* c) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  while (is_user_vaddr(c) && pagedir_get_page(pd, pg_round_down(c))) {
    if (*c == '\0') {
      return true;
    }
    c++;
  }
  return false;
}

bool is_valid_args(const void* c) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  return is_user_vaddr(c) && pagedir_get_page(pd, c);
}

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

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
    sys_exit(f, -1);
  }
  f->eax = process_execute(cmd_line);
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
    decrement_children_ref_cnt(pcb);
    decrement_ref_cnt(pcb->curr_as_child);
    pcb->curr_as_child->exit_status = status;
    sema_up(&pcb->curr_as_child->wait_sema);
    process_exit();
}

// void file_create(struct intr_frame f, const char* file, unsigned initial_size) {
  
// }

int file_read(struct intr_frame* f, int fd, void* buffer, unsigned length) {

}

int file_write(struct intr_frame* f, int fd, const void* buffer, unsigned length) {

}

void file_seek(struct intr_frame* f, int fd, unsigned position) {

}

unsigned file_tell(struct intr_frame* f, int fd) {

}

void file_close(struct intr_frame* f, int fd) {

}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  int num_args = 0;
  switch(args[0]) {
    case SYS_WRITE: case SYS_READ:
      num_args = 3;
      break;
    case SYS_CREATE: case SYS_SEEK:
      num_args = 2;
      break;
    default:
      num_args = 1;
      break;
  }
  for (int i = 1; i <= num_args; i++) {
    if (!is_valid_args(args[i])) {
      printf("%d is not in userspace.", args[i]);
      process_exit();
    }
  }

  switch(args[0]) {
    case SYS_PRACTICE:
      sys_practice(f, args[1]);
      break;
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_WAIT:
      break;
    case SYS_EXEC:
      break;
    case SYS_EXIT:
      break;
    /* File operations */
    case SYS_CREATE:
      file_create(f, args[1], args[2]);  /* Working On */
      break;
    case SYS_REMOVE:
      file_remove(f, args[1]);  /* Pending */
      break;
    case SYS_OPEN:
      file_open(f, args[1]);    /* Pending */
      break;
    case SYS_FILESIZE:
      file_filesize(f, args[1]);/* Pending */
      break;
    case SYS_READ:
      file_read(f, args[1], args[2], args[3]);    /* Pending */
      break;
    case SYS_WRITE:
      file_write(f, args[1], args[2], args[3]);   /* Pending */
      break;
    case SYS_SEEK:
      file_seek(f, args[1], args[2]);    /* Pending */
      break;
    case SYS_TELL:
      file_tell(f, args[1]);    /* Pending */
      break;
    case SYS_CLOSE:
      file_close(f, args[1]);   /* Pending */
      break;
  }
}
