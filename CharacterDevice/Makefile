obj-m+=char_dev_example.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) char_dev_test.c -o char_dev_test
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean