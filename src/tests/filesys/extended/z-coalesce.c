/* cache should coalesce multiple block write into one. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define BLOCK_SIZE 512

const char* file_name = "coalesce";
const unsigned int file_size = 64 * (1 << 10);

/* open a file, read the file, close the file */
void read_file() {
  unsigned long long read_cnt = 0;
  char buffer[1];
  int fd;
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  msg("reading \"%s\"", file_name);
  while (read_cnt < file_size) {
    read_cnt += read(fd, buffer, 1);
  }
  msg("close \"%s\"", file_name);
  close(fd);
}

/* open a file, write the file, close the file */
void write_file() {
  unsigned long long write_cnt = 0;
  char buffer[1];
  buffer[0] = 0;
  int fd;
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  msg("writing \"%s\"", file_name);
  while (write_cnt < file_size) {
    write_cnt += write(fd, buffer, 1);
  }
  msg("close \"%s\"", file_name);
  close(fd);
}

void test_main(void) {
  CHECK(create(file_name, file_size), "create \"%s\"", file_name);
  cache_reset();
  int block_write_before = fs_device_write();
  write_file();
  read_file();
  int block_write_after = fs_device_write();
  ASSERT((64 <= block_write_after - block_write_before) || (block_write_after - block_write_before <= 256));
  CHECK(remove(file_name), "remove \"%s\"", file_name);
  return;
}
