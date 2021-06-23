all:	login logout password loggedin logincheck envcgi changepassword

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

COMPFLAGS=-fPIC -g -O -ISQLlib -D_GNU_SOURCE --std=gnu99 -Wall -Wextra -funsigned-char ${SQLINC}
LINKFLAGS=${CCFLAGS} ${SQLLIB} -lcrypto -lssl

envcgi: envcgi.o errorwrap.o
	gcc -o $@ $< ${LINKFLAGS} errorwrap.o

envcgi.o: envcgi.c envcgi.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

password: password.o
	gcc -o $@ $< ${LINKFLAGS}

password.o: password.c password.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

menuconfig:
	kconfig-mconf Kconfig

.config: Kconfig Makefile
	kconfig-mconf Kconfig

config.h: .config
	sed -e '/^$$/d' -e '/#.*/d' -e 's/^/#define /' -e 's/=/ /' $< > $@
