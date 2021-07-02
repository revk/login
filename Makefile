all:	password envcgi loggedin logincheck dologin dologout changepassword weblink redirect

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

update:
	git submodule update --init --remote --recursive
	git commit -a -m "Library update"
	git push

ifndef KCONFIG_CONFIG
KCONFIG_CONFIG=../login.conf
endif

COMPFLAGS=-fPIC -g -O -ISQLlib -D_GNU_SOURCE --std=gnu99 -Wall -Wextra -funsigned-char ${SQLINC}
LINKFLAGS=${COMPFLAGS} ${SQLLIB} -lcrypto -lssl

SQLlib/sqllib.o: SQLlib/sqllib.c
	make -C SQLlib

weblink: weblink.c base64.o password redirect.o
	gcc -o $@ $< base64.o -lpopt -DSECRET=`./password` redirect.o ${LINKFLAGS}

envcgi: envcgi.c envcgi.o errorwrap.o redirect.o base64.o password
	gcc -o $@ $< errorwrap.o redirect.o base64.o -DSECRET=`./password` ${LINKFLAGS}

envcgi.o: envcgi.c envcgi.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

password: password.c password.o
	gcc -o $@ $< -lm -lpopt ${LINKFLAGS}

password.o: password.c password.h config.h xkcd936-wordlist.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

loggedin: envcgi.c logincheck.o hashes.o redirect.o selectdb.o base64.o
	gcc -o $@ $< logincheck.o errorwrap.o redirect.o -DPLUGIN=logincheck -lm -lpopt SQLlib/sqllib.o hashes.o selectdb.o base64.o -largon2 ${LINKFLAGS}

logincheck: envcgi.c logincheck.o hashes.o redirect.o selectdb.o base64.o
	gcc -o $@ $< logincheck.o errorwrap.o redirect.o -DPLUGIN=logincheck -DNONFATAL -lm -lpopt SQLlib/sqllib.o hashes.o selectdb.o base64.o -largon2 ${LINKFLAGS}

logincheck.o: logincheck.c config.h SQLlib/sqllib.o config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

dologin: dologin.c dologin.o hashes.o redirect.o selectdb.o logincheck.o base64.o
	gcc -o $@ $< -lm -lpopt SQLlib/sqllib.o redirect.o hashes.o selectdb.o logincheck.o base64.o -largon2 ${LINKFLAGS}

dologin.o: dologin.c dologin.h SQLlib/sqllib.o config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

dologout: dologout.c dologout.o redirect.o selectdb.o
	gcc -o $@ $< -lm -lpopt SQLlib/sqllib.o redirect.o selectdb.o ${LINKFLAGS}

dologout.o: dologout.c dologout.h SQLlib/sqllib.o config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

changepassword: changepassword.c changepassword.o logincheck.o hashes.o selectdb.o base64.o redirect.o
	gcc -o $@ $< -lm -lpopt SQLlib/sqllib.o logincheck.o hashes.o selectdb.o base64.o redirect.o -largon2 ${LINKFLAGS}

changepassword.o: changepassword.c changepassword.h SQLlib/sqllib.o config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

hashes.o: hashes.c hashes.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

redirect: redirect.c redirect.o
	gcc -o $@ $< ${LINKFLAGS}

redirect.o: redirect.c redirect.h config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

selectdb.o: selectdb.c selectdb.h SQLlib/sqllib.o config.h
	gcc -c -o $@ $< -DLIB ${COMPFLAGS}

menuconfig:
	./makek ${KCONFIG_CONFIG} config.h

config.h: ${KCONFIG_CONFIG}
	./makek ${KCONFIG_CONFIG} config.h

${KCONFIG_CONFIG}: Kconfig
	./makek ${KCONFIG_CONFIG} config.h
