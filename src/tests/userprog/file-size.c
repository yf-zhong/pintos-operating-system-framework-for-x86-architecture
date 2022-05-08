/* test on getting the size of a file. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int fd = open("sample.txt");
  int size = filesize(fd);
  if (size != 239)
    fail("filesize() returned %d", size);
}