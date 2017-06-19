# basic Makefile to hook into the kernel build system
obj-m := snitchd.o

KERNEL_VERSION ?= $(shell uname -r)
MAKEMOD := $(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(shell pwd)

.PHONY: default clean

default: snitchd-$(KERNEL_VERSION).ko

first_names.rl: census-derived-all-first.txt format_names.py
	python format_names.py firstname census-derived-all-first.txt > $@

last_names.rl: census-dist-2500-last.txt format_names.py
	python format_names.py lastname census-dist-2500-last.txt > $@

FedACHdir.txt:
	@echo "Please manually accept the license and download the FedACHdir.txt file from https://www.frbservices.org/EPaymentsDirectory/FedACHdir.txt (it can't be distributed here for licensing reasons)."
	@exit 1

routing_numbers.rl: format_ach.py FedACHdir.txt
	python format_ach.py routingnumber FedACHdir.txt > $@

snitchd.c: snitchd.rl first_names.rl last_names.rl routing_numbers.rl
	ragel -C snitchd.rl -o $@

snitchd.graphviz: snitchd.rl
	ragel -C $? -Vp -o $@

snitchd.pdf: snitchd.graphviz
	dot $? -T pdf -o $@

snitchd-$(KERNEL_VERSION).ko: snitchd.c
	$(MAKEMOD) modules
	strip --strip-unneeded snitchd.ko
	mv snitchd.ko $@

clean:
	rm -rf *.o *.cmd .*.cmd *.mod.c modules.order Module.symvers *.ko .tmp_versions
