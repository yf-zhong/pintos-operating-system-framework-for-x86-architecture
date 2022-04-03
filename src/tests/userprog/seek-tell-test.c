/* test on seeking and telling a file. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int fd = open("sample.txt");
  int pos = tell(fd);
  if (pos != 0)
    fail("tell() returned %d", pos);
  seek(fd, 52);
  pos = tell(fd);
  if (pos != 52)
    fail("seek() should move next read/write to 52 but tell() returned %d", pos);
  seek(fd, 520);
  pos = tell(fd);
  if (pos != 520)
    fail("seek() should move next read/write to 52 + 520 = 572 but tell() returned %d", pos);
}