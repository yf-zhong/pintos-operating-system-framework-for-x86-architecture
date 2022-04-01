#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <stdint.h>
#include <limits.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define ERROR -1


/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Lock for the file system operation */
struct lock file_sys_lock;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct thread_info {
  tid_t tid;
  bool is_exited;
  struct thread* t;
  struct list_elem proc_elem;
};

struct died_thread {
  tid_t tid;
  struct list_elem;
};

typedef struct child {
  pid_t pid;
  struct semaphore exec_sema;
  struct semaphore wait_sema;
  int exit_status;
  bool is_exited;
  bool is_waiting;
  int ref_cnt;
  struct lock ref_lock;
  struct list_elem elem;
} CHILD;

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct list children;
  struct child* curr_as_child;
  char *file_name;
  struct file* curr_executable;
  int cur_fd;                 /* The fd number assigned to new file */
  struct list file_descriptor_table; /* All the files opened in current process */

  /* for project 2 task 3 */
  struct list died_thread_list;
  struct list thread_list;
  struct lock lock_table[CHAR_MAX + 1]; // an array to store all the locks for this process
  int num_locks;    
  struct semaphore sema_table[CHAR_MAX + 1]; // an array to store all the semaphores for this process
  int num_semas;
  struct lock process_lock;
  void* highest_upage;
  bool is_exiting; // check everytime after switch_threads, if true, exit the current thread
  bool is_main_exiting;
};

/* One element in the file descriptor table */
struct file_descriptor {
   int fd;                   /* File descriptor */
   struct file *file;        /* File description */
   struct list_elem elem;
};

// NEW_c has to come first so that 
// FILE_NAME can have the remaining space
typedef struct start_proc_arg {
  struct child* new_c;
  char* file_name;
} SPA;

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

/* Iterater through file descriptor table to find fd. */
struct file_descriptor* find_file_des(int);
tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
