all:	password envcgi loggedin logincheck dologin dologout changepassword

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

envcgi: envcgi.c envcgi.o errorwrap.o redirect.o
	gcc -o $@ $< ${LINKFLAGS} errorwrap.o redirect.o

envcgi.o: envcgi.c envcgi.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

password: password.c password.o
	gcc -o $@ $< ${LINKFLAGS} -lm -lpopt

password.o: password.c password.h config.h xkcd936-wordlist.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

loggedin: envcgi.c logincheck.o hashes.o redirect.o selectdb.o
	gcc -o $@ $< logincheck.o errorwrap.o redirect.o -DPLUGIN=logincheck ${LINKFLAGS} -lm -lpopt SQLlib/sqllib.o hashes.o -largon2 selectdb.o

logincheck: envcgi.c logincheck.o hashes.o redirect.o selectdb.o
	gcc -o $@ $< logincheck.o errorwrap.o redirect.o -DPLUGIN=logincheck -DNONFATAL ${LINKFLAGS} -lm -lpopt SQLlib/sqllib.o hashes.o -largon2 selectdb.o

logincheck.o: logincheck.c config.h SQLlib/sqllib.o
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

dologin: dologin.c dologin.o hashes.o redirect.o selectdb.o
	gcc -o $@ $< ${LINKFLAGS} -lm -lpopt SQLlib/sqllib.o redirect.o -largon2 hashes.o selectdb.o

dologin.o: dologin.c dologin.h SQLlib/sqllib.o
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

dologout: dologout.c dologout.o redirect.o selectdb.o
	gcc -o $@ $< ${LINKFLAGS} -lm -lpopt SQLlib/sqllib.o redirect.o selectdb.o

dologout.o: dologout.c dologout.h SQLlib/sqllib.o
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

changepassword: changepassword.c changepassword.o logincheck.o hashes.o selectdb.o
	gcc -o $@ $< ${LINKFLAGS} -lm -lpopt SQLlib/sqllib.o logincheck.o hashes.o -largon2 selectdb.o

changepassword.o: changepassword.c changepassword.h SQLlib/sqllib.o
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

hashes.o: hashes.c hashes.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

redirect.o: redirect.c redirect.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

selectdb.o: selectdb.c selectdb.h SQLlib/sqllib.o
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

menuconfig:
	kconfig-mconf Kconfig
	touch .config

.config: Kconfig
	kconfig-mconf Kconfig
	touch .config

config.h: .config
	sed -e 's/^#/\/\//' -e 's/^CONFIG_/#define CONFIG_/' -e 's/=/ /' $< > $@
