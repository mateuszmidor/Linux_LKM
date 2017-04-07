obj-m += firewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	g++ -std=c++11 client.cpp -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f client