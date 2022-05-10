#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock filesys_lock; //defined at userprog/syscall.h

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock); //initialize lock
}

	/* Must make exception for the following cases.
	 1.  invalid pointer
	 2.  pointer into kernel memory
	 3.  block partially on one of those regions.
	for those cases -> exit(0) */

void pointer_validity(void * addr) {
	if (addr == NULL || is_kernel_vaddr(addr)) 
		exit(-1);
	/* if addr is not allocated in thread's own address range, return -1 */
	if (!pml4_get_page (thread_current()->pml4, addr))
		exit(-1);
}

/* The main system call interface */
/* intr_frame f is caller's intr_frame */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	// We should implement all this functions. Fuck. Simal?
	switch (f->R.rax) {
		case SYS_HALT :
			//printf("SYS_HALT\n");
			halt();
			break;
		case SYS_EXIT :
			//printf("SYS_EXIT\n");
			exit(f->R.rdi);
			break;
		case SYS_FORK :
			//printf("SYS_FORK\n");
			memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame));
			f->R.rax = (uint64_t)fork(f->R.rdi);
			break;
		case SYS_EXEC :
			//printf("SYS_EXEC\n");
			f->R.rax = (uint64_t)exec(f->R.rdi);
			break;
		case SYS_WAIT :
			//printf("SYS_WAIT pid: %d\n",f->R.rdi);
			f->R.rax = (uint64_t)wait(f->R.rdi);
			break;
		case SYS_CREATE :
			//printf("SYS_CREATE\n");
			f->R.rax =(uint64_t)create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE :
			//printf("SYS_REMOVE\n");
			f->R.rax =(uint64_t)remove(f->R.rdi);
			break;
		case SYS_OPEN :
			//printf("SYS_OPEN\n");
			f->R.rax =(uint64_t)open(f->R.rdi);
			break;
		case SYS_FILESIZE :
			//printf("SYS_FILESIZE\n");
			f->R.rax =(uint64_t)filesize(f->R.rdi);
			break;
		case SYS_READ :
			//printf("SYS_READ\n");
			f->R.rax =(uint64_t)read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE :
			//printf("SYS_WRITE\n");
			f->R.rax =(uint64_t)write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK :
			//printf("SYS_SEEK\n");
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL :
			//printf("SYS_TELL\n");
			f->R.rax =(uint64_t)tell(f->R.rdi);
			break;
		case SYS_CLOSE :
			//printf("SYS_CLOSE\n");
			close(f->R.rdi);
			break;
		default :
			exit(-1);
	}
	//thread_exit ();
}
 
void halt (void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current ();
	curr -> exit_status = status;
	printf ("%s: exit(%d)\n", curr-> name, curr -> exit_status);
	thread_exit();
}

/* Is this the best solution? hmm...*/
/* ★ Do this after finishing file-related functions ★ */
pid_t fork (const char *thread_name){
	pointer_validity(thread_name);
	//printf("fork rsp: %p\n",thread_current()->parent_if.rsp);
	return process_fork(thread_name, &thread_current()->parent_if);
}

int exec (const char *file){
	pointer_validity(file);
	/* if we use const char as argument, sometimes we can't acccess it 
	in process_exec. So, copy it */
	char *file_copy = palloc_get_page(PAL_ZERO);
	if (!file_copy)
		return -1;
	strlcpy(file_copy, file, strlen(file)+1);
	int ret = process_exec(file_copy);
	if (ret == -1) {
		exit(-1);
		return -1;
	}
	/* cannot be reached here */
}

int wait (pid_t pid){
	return process_wait(pid);
}

/* At filesys/filesys.c */
bool create (const char *file, unsigned initial_size){
	pointer_validity(file);
	return filesys_create (file, initial_size);
}

bool remove (const char *file){
	pointer_validity(file);
	return filesys_remove (file);
}

int open (const char *file){
	struct thread *t = thread_current();
	int fd = -1;
	pointer_validity(file);
	/* we should make file descriptor(fd) in thread structure 
	and allocate fd to FILE */
	/* struct file is defined at filesys/file.c */
	struct file *opened = filesys_open(file);
	if (opened == NULL)
		return -1;

	for (int i = 3; i < 128; i++) { //except STDIN, STDOUT, STDERR
		if (t->file_descriptor[i] == NULL) {
			t->file_descriptor[i] = opened;
			fd = i;
			break;
		}
	}

	if (fd < 0) {
		file_close(opened);
		return -1;
	}

	return fd;
}

int filesize (int fd){
	struct file *cur_file = thread_current()->file_descriptor[fd];
	if (cur_file == NULL)
		return -1;
	
	/* struct inode is defined at filesys/inode.c */
	return (int)file_length(cur_file);
}

int read (int fd, void *buffer, unsigned length){
	pointer_validity(buffer);

	/* check invalid fd */
	if (fd < 0 || fd > 127)
		return -1;

	lock_acquire(&filesys_lock);

	/* fd 0 reads from the keyboard using input_getc() 
		-> defined at devices/input.c */
	if (fd == 0) {
		unsigned i = 0;
		for (; i < length; i++){
			uint8_t input = input_getc();
			*(uint8_t *)buffer = input;
			buffer++;
			if (input == 0)
				break;
		}
		lock_release(&filesys_lock);
		return (int) i;
	}

	struct file *cur_file = thread_current()->file_descriptor[fd];
	if (cur_file == NULL)
		return -1;

	/* defined at filesys/file.c */
	int ret = (int)file_read(cur_file, buffer, length);
	lock_release(&filesys_lock);

	return ret;
}

int write (int fd, const void *buffer, unsigned length){
	pointer_validity(buffer);

	/* check invalid fd */
	if (fd < 0 || fd > 127)
		return -1;

	/* fd 1 writes to the console. Your code to write to the console 
	should write all of buffer in one call to putbuf()
		-> defined at lib/kernel/console.c */
	if (fd == 1) {
		putbuf (buffer, length);
		return length;
	}

	lock_acquire(&filesys_lock);

	struct file *cur_file = thread_current()->file_descriptor[fd];
	if (cur_file == NULL)
		return -1;

	/* Writing past end-of-file would normally extend the file, 
	but file growth is not implemented by the basic file system. 
	The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, 
	or 0 if no bytes could be written at all. */
	//printf("file to write:%p\n", cur_file);
	int ret = (int)file_write(cur_file, buffer, length);
	lock_release(&filesys_lock);
	return ret;
}

void seek (int fd, unsigned position){
	file_seek(thread_current()->file_descriptor[fd], position);
}

unsigned tell (int fd){
	return file_tell(thread_current()->file_descriptor[fd]);
}

void close (int fd){
	if (fd < 0 || fd > 128)
		return;
	
	struct file *cur_file = thread_current()->file_descriptor[fd];
	if (cur_file == NULL)
		return;
	lock_acquire(&filesys_lock);

	file_close(cur_file);
	thread_current()->file_descriptor[fd] = NULL;

	lock_release(&filesys_lock);
}