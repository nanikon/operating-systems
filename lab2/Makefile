obj-m += kerner-mode.o
 
PWD := $(CURDIR)
 
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load: all
	sudo insmod kerner-mode.ko
	sudo chmod a+rw /proc/lab2_os_module

unload:
	sudo rmmod kerner-mode

user: user-mode.c
	gcc -o user-mode user-mode.c

fpu_example.o: fpu_example.asm
	nasm -f elf64 fpu_example.asm -o fpu_example.o

fpu_example: fpu_example.o
	ld -o fpu_example fpu_example.o
