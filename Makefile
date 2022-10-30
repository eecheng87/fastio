SUBDIRS := module wrapper
TOPTARGETS := all clean

PWD := $(shell pwd)
OUT := downloads

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

reload:
	sudo dmesg -C
	-sudo rmmod mlioo
	sudo insmod module/mlioo.ko

format:
	find module/ -iname *.h -o -iname *.c -type f | xargs clang-format -i -style=WebKit
	find wrapper/ -iname *.h -o -iname *.c -type f | xargs clang-format -i -style=WebKit
	find echo/ -iname *.h -o -iname *.c -type f | xargs clang-format -i -style=WebKit

clean-out:
	rm -rf $(OUT)
	rm -rf local
	rm -rf auth

recover:
	git checkout HEAD -- configs/nginx.conf wrapper/ngx.c module/include/esca.h esca.conf

.PHONY: $(TOPTARGETS) $(SUBDIRS) $(NGX) $(LIGHTY)
