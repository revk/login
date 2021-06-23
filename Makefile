all:	password envcgi login logout loggedin logincheck changepassword

ifneq ($(wildcard /usr/bin/mysql_config),)
SQLINC=$(shell mysql_config --include)
SQLLIB=$(shell mysql_config --libs)
SQLVER=$(shell mysql_config --version | sed 'sx\..*xx')
endif
ifneq ($(wildcard /usr/bin/mariadb_config),)
SQLINC=$(shell mariadb_config --include)
SQLLIB=$(shell mariadb_config --libs)
SQLVER=$(shell mariadb_config --version | sed 'sx\..*xx')
endif

COMPFLAGS=-fPIC -g -O -ISQLlib -D_GNU_SOURCE --std=gnu99 -Wall -Wextra -funsigned-char ${SQLINC} -DBUILDTIME=`date +%FT%T.%N`
LINKFLAGS=${COMPFLAGS} ${SQLLIB} -lcrypto -lssl

SQLlib/sqllib.o: SQLlib/sqllib.c
	make -C SQLlib

envcgi: envcgi.c envcgi.o errorwrap.o
	gcc -o $@ $< ${LINKFLAGS} errorwrap.o

envcgi.o: envcgi.c envcgi.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

password: password.c password.o
	gcc -o $@ $< ${LINKFLAGS} -lm -lpopt

password.o: password.c password.h config.h xkcd936-wordlist.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

menuconfig:
	kconfig-mconf Kconfig
	touch .config

.config: Kconfig
	kconfig-mconf Kconfig
	touch .config

config.h: .config
	sed -e 's/^#/\/\//' -e 's/^CONFIG_/#define CONFIG_/' -e 's/=/ /' $< > $@
