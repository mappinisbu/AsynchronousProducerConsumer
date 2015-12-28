obj-m += sys_submitjob.o
#obj-m += kernelsock_test.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xhw3 submitjob usersubmitjob

xhw3: xhw3.c
	gcc -Wall -Werror xhw3.c -o xhw3

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#kernelsock_test:
#	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

usersubmitjob: user_submitjob.c
	gcc -Wall -Werror -lssl user_submitjob.c -o user_submitjob 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3
	rm -f user_submitjob

