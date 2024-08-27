OBJ=lsm_module
KPATH:=/lib/modules/$(shell uname -r)/build
$(OBJ)-objs := setpage.o
${OBJ}-objs += symbol.o
${OBJ}-objs += main.o
obj-m := $(OBJ).o
all:
	make -C $(KPATH) M=$(PWD) modules
clean:
	make -C $(KPATH) M=$(PWD) clean
