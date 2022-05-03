/* test hot cache performance should be better than code cache performance. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define BLOCK_SIZE 512

const char* file_name = "test";
const int file_size = 2 * BLOCK_SIZE;

/* open a file, read the file, close the file */
void read_file() {
  int read_cnt = 0;
  char buffer[file_size];
  int fd;
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  msg("reading \"%s\"", file_name);
  while (read_cnt < file_size) {
    read_cnt += read(fd, buffer, file_size - read_cnt);
  }
  msg("close \"%s\"", file_name);
  close(fd);
}

void test_main(void) {
  CHECK(create(file_name, file_size), "create \"%s\"", file_name);
  cache_reset();
  read_file();
  int cold_cache_hit_cnt = cache_hit_cnt();
  int cold_cache_miss_cnt = cache_miss_cnt();
  double cold_cache_hit_rate = ((double) cold_cache_hit_cnt) / (cold_cache_hit_cnt + cold_cache_miss_cnt);

  read_file();
  int hot_cache_hit_cnt = cache_hit_cnt() - cold_cache_hit_cnt;
  int hot_cache_miss_cnt = cache_miss_cnt() - cold_cache_miss_cnt;
  double hot_cache_hit_rate = ((double) hot_cache_hit_cnt) / (hot_cache_hit_cnt + hot_cache_miss_cnt);
  CHECK(remove(file_name), "remove \"%s\"", file_name);
  ASSERT(cold_cache_hit_rate < hot_cache_hit_rate);  
  return;
}



