%.o: %.c
	clang-12 -target bpf -g -O1 -c -o $@ $<

all: context.o map.o time1.o time2.o
