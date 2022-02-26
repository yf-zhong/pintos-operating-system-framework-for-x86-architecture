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

static void syscall_handler(struct intr_frame*);

bool is_valid_char_ptr(const char*);
void sys_practice(struct intr_frame*, int);
void sys_halt(void);
void sys_exec(struct intr_frame*, const char*);
void sys_wait(struct intr_frame*, pid_t);
void sys_exit(struct intr_frame*, int);

bool file_create(const char* file, unsigned initial_size);
bool file_remove(const char* file);
int file_open(const char* file);
int file_filesize(int fd);
int file_read(int fd, void* buffer, unsigned length);
int file_write(int fd, const void* buffer, unsigned length);
void file_seek(int fd, unsigned position);
unsigned file_tell(int fd);
void file_close(int fd);

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

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
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
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
  }
}
