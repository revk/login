// Logged in check

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <sqllib.h>
#include "envcgi.h"
#include "logincheck.h"

int logincheck(const char *session)
{                               // Do plugin checks after envcgi has set session and environment and so on - return 0 if OK
 // Clearing some variables
 if(*CONFIG_ENV_USER_ID)unsetenv(CONFIG_ENV_USER_ID);

		 // Check login
 SQL sql;
 sql_cnf_connect(&sql,CONFIG_DB_CONF);
#ifdef CONFIG_DB_DATABASE
 if(*CONFIG_DB_DATABASE)sql_safe_select_db(&sql,CONFIG_DB_DATABASE);
#endif


 sql_close(&sql);
}
