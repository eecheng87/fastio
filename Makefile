SUBDIRS := module
TOPTARGETS := all clean

PWD := $(shell pwd)
OUT := downloads

REDIS_SOURCE := https://github.com/redis/redis/archive/refs/tags/v1.3.12.zip
REDIS_NAME := redis-1.3.12
REDIS_ZIP_NAME := v1.3.12
REDIS_PATH := $(REDIS_NAME)
REDIS := redis

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

redis:
	@echo "download redis..."
	wget $(REDIS_SOURCE)
	unzip $(REDIS_ZIP_NAME).zip
	rm $(REDIS_ZIP_NAME).zip
	cd $(REDIS_PATH) && patch -p2 -i ../patches/redis.patch
	cd $(REDIS_PATH) && make -j$(nproc)

clean-out:
	rm -rf $(OUT)
	rm -rf local
	rm -rf auth

recover:
	git checkout HEAD -- configs/nginx.conf wrapper/ngx.c module/include/esca.h esca.conf

.PHONY: $(TOPTARGETS) $(SUBDIRS) $(NGX) $(LIGHTY)
