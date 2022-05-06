#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/float.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"

static void syscall_handler(struct intr_frame*);

bool is_valid_addr(uint32_t);
bool is_valid_str(const char*);
void sys_practice(struct intr_frame*, int);
void sys_halt(void);
void sys_exec(struct intr_frame*, const char*);
void sys_wait(struct intr_frame*, pid_t);
void sys_exit(struct intr_frame*, int);

bool is_valid_addr(uint32_t addr) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  for (int i = 0; i < 4; i++) {
    if (!(is_user_vaddr((const char *) addr + i) && pagedir_get_page(pd, (const char *) addr + i))) {
      return false;
    }
  }
  return true;
}

bool is_valid_str(const char* c) {
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
}

void sys_practice(struct intr_frame* f, int i) {
  f->eax = i + 1;
  return;
}

void sys_halt() {
  shutdown_power_off();
}

void sys_exec(struct intr_frame* f, const char* cmd_line) {
  if (is_valid_str(cmd_line)) {
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
    struct process* pcb = thread_current()->pcb;
    pcb->curr_as_child->exit_status = status;
    process_exit();
}

void sys_create(struct intr_frame* f, const char* file, unsigned initial_size) {  
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  /* Get current user program pcb */
  bool flag;
  flag = filesys_create(file, initial_size);
  f->eax = flag;
  return;
}

void sys_remove(struct intr_frame* f, const char* file) {
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  bool flag;
  flag = filesys_remove(file);
  f->eax = flag;
  return;
}

void sys_open(struct intr_frame* f, const char* file) {
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  struct process* pcb = thread_current()->pcb;
  bool is_dir = false;
  struct file *new_file = filesys_open(file, &is_dir);
  if (!new_file) {
    f->eax = -1;
    return;
  }
  struct file_descriptor *new_file_descriptor = (struct file_descriptor *) malloc(sizeof(struct file_descriptor));
  if (!new_file_descriptor) {
    sys_exit(f, -1);
  }
  new_file_descriptor->fd = pcb->cur_fd++;
  new_file_descriptor->file = new_file;
  new_file_descriptor->is_directory = is_dir;
  list_push_back(&(pcb->file_descriptor_table) ,&(new_file_descriptor->elem));
  f->eax = new_file_descriptor->fd;
  return;
}

void sys_filesize(struct intr_frame* f, int fd) {
  if (fd <= 1) {
    sys_exit(f, -1);
  }
  off_t file_size;
  struct file_descriptor *my_file_des = find_file_des(fd);
  if (!my_file_des) {
    sys_exit(f, -1);
  }
  file_size = file_length(my_file_des->file);
  f->eax = file_size;
  return;
}

void sys_read(struct intr_frame* f, int fd, void* buffer, unsigned size) {
  if (!buffer) {
    sys_exit(f, -1);
  }
  if (!is_valid_addr((uint32_t)buffer)) {
    sys_exit(f, -1);
  }
  off_t number_read = 0;
  if (fd == 0) {
    for (unsigned i = 0; i < size; i++) {
      number_read += input_getc();
    }
    return;
  } else if (fd == 1 || fd < 0) {
    sys_exit(f, -1);
  }
  struct file_descriptor *my_file_des = find_file_des(fd);
  if (!my_file_des || my_file_des->is_directory) {
    sys_exit(f, -1);
  }
  number_read = file_read(my_file_des->file, buffer, size);
  f->eax = number_read;
  return;
}

void sys_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  /* Argument validation (may need to test whether buffer is big enough) */
  if (!is_valid_addr((uint32_t)buffer)) {
    sys_exit(f, -1);
  }
  if (fd == 1) {
    putbuf(buffer, size);
  } else if (fd <= 0) {
    sys_exit(f, -1);
  } else {
    struct file_descriptor *my_file_des = find_file_des(fd);
    if (!my_file_des || my_file_des->is_directory) {
      sys_exit(f, -1);
    }
    int bytes_read;
    bytes_read = file_write(my_file_des->file, buffer, size);
    f->eax = bytes_read;
    return;
    
  }
  return;
}

void sys_seek(struct intr_frame* f, int fd, unsigned position) {
  if (fd <= 1) {
    printf("fd: %d can't be seeked. (Either it is a stdin, out, err, or invalid)", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    file_seek(my_file_des->file, position);
    f->eax = 0;
    return;
  }
  f->eax = -1;
  return;
}

void sys_tell(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    f->eax = file_tell(my_file_des->file);
    return;
  }
  f->eax = -1;
  return;
}

void sys_close(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    file_close(my_file_des->file);
    f->eax = 0;
    list_remove(&my_file_des->elem);
    free(list_entry(&my_file_des->elem, struct file_descriptor, elem));
    return;
  }
  f->eax = -1;
  return;
}

void sys_comp_e(struct intr_frame* f, int num) {
  if (num <= 0) {
    printf("n: %d is invalid.", num);
    f->eax = -1;
    return;
  }
  f->eax = sys_sum_to_e(num);
  return;
}

void sys_chdir(struct intr_frame* f, const char* dir) {
  struct dir* d = tracing(dir, false);
  if (d == NULL) {
    f->eax = false;
    return;
  }
  thread_current()->pcb->cwd = d;
  f->eax = true;
}

void sys_mkdir(struct intr_frame* f, const char* dir) {
  block_sector_t inode_sector = 0;
  struct dir* d = tracing(dir, true);
  if (d == NULL) {
    f->eax = false;
    return;
  }
  char name[NAME_MAX + 1];
  get_last_name(dir, name);
  if (free_map_allocate(1, &inode_sector) && dir_create(inode_sector, 2) && dir_add(d, name, inode_sector, true)) {
    struct dir* new_d = dir_open(inode_open(inode_sector));
    dir_add(new_d, ".", inode_sector, true);
    dir_add(new_d, "..", get_inode_sector(d), true);
    dir_close(new_d);
    dir_close(d);
    f->eax = true;
  } else {
    dir_close(d);
    f->eax = false;
  }
}

void sys_readdir(struct intr_frame* f, int fd, char* name) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (!my_file_des->is_directory) {
    f->eax = false;
    return;
  }
  struct inode* inode = file_get_inode(my_file_des->file);
  struct dir* dir = dir_open(inode);
  bool result = dir_readdir(dir, name);
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
    result = dir_readdir(dir, name);
  }
  dir_close(dir);
  f->eax = result;
}

void sys_isdir(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (!my_file_des->is_directory) {
    f->eax = false;
  } else {
    f->eax = true;
  }
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

   /* Validate stack pointer */
  if (!is_valid_addr((uint32_t)args)) {
    sys_exit(f, -1);
  }

  int num_args = 0;
  switch(args[0]) {
    case SYS_WRITE:
    case SYS_READ:
      num_args = 3;
      break;
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_READDIR:
      num_args = 2;
      break;
    case SYS_PRACTICE:
    case SYS_EXIT:
    case SYS_HALT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_CHDIR:
    case SYS_MKDIR:
    case SYS_ISDIR:
      num_args = 1;
      break;
    default:
      num_args = 0;
  }

  if (!is_user_vaddr(args + num_args)) {
    sys_exit(f, -1);
  }

  switch(args[0]) {
    case SYS_PRACTICE:
      sys_practice(f, args[1]);
      break;
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_WAIT:
      sys_wait(f, args[1]);
      break;
    case SYS_EXEC:
      if (((sizeof(pid_t) - 1) & (unsigned long) &args[1]) || !is_valid_addr((uint32_t) &args[1])) {
        sys_exit(f, -1);
      }
      sys_exec(f, (char*) args[1]);
      break;
    case SYS_EXIT:
      sys_exit(f, args[1]);
      break;

    /* File operations */
    case SYS_CREATE:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_create(f, (const char*) args[1], args[2]);
      break;
    case SYS_REMOVE:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_remove(f, (const char*) args[1]);
      break;
    case SYS_OPEN:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_open(f, (const char*) args[1]);
      break;
    case SYS_FILESIZE:
      sys_filesize(f, args[1]);
      break;
    case SYS_READ:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
        sys_exit(f, -1);
      }
      sys_read(f, args[1], (void*) args[2], args[3]);
      break;
    case SYS_WRITE:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
        sys_exit(f, -1);
      }
      sys_write(f, args[1], (const void*) args[2], args[3]);
      break;
    case SYS_SEEK:
      sys_seek(f, args[1], args[2]);
      break;
    case SYS_TELL:
      sys_tell(f, args[1]);
      break;
    case SYS_CLOSE:
      sys_close(f, args[1]);
      break;

    /* FPU ops */
    case SYS_COMPUTE_E:
      sys_comp_e(f, args[1]);
      break;

    /* Subdirectories */
    case SYS_CHDIR:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_chdir(f, (const char*) args[1]);
      break;
    case SYS_MKDIR:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_mkdir(f, (const char*) args[1]);
      break;
    case SYS_READDIR:
      if ((sizeof(char*) - 1) & (unsigned long) &args[2]) {
        sys_exit(f, -1);
      }
      sys_readdir(f, args[1], (char*) args[2]);
      break;
    case SYS_ISDIR:
      sys_isdir(f, args[1]);
      break;
    
    default:
      f->eax = -1; /* If the NUMBER is not defined */
  }
}
