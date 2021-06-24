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
#include "dologin.h"
#include "logincheck.h"

const char *logincheck(const char *session)
{                               // Do plugin checks after envcgi has set session and environment and so on - return 0 if OK
#ifdef  CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
   // Clearing user ID
   if (*CONFIG_ENV_USER_ID)
      unsetenv(CONFIG_ENV_USER_ID);
   // Check login
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
#ifdef CONFIG_DB_DATABASE
   if (*CONFIG_DB_DATABASE)
      sql_safe_select_db(&sql, CONFIG_DB_DATABASE);
#else
   const char *v;
   if (*CONFIG_ENV_DB && !(v = getenv(CONFIG_ENV_DB)) || !*v)
      return "No database";
   sql_safe_select_db(&sql, v);
#endif
   SQL_RES *res = NULL;
   const char *check(void) {
#ifdef CONFIG_DB_SEPARATE_SESSION
      res = sql_safe_query_store_free(&sql, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_SESSION_TABLE, CONFIG_DB_SESSION_FIELD, session));
      if (!sql_fetch_row(res))
         return "Not logged in";
      const char *uid = sql_col(res, CONFIG_DB_SESSION_USER_LINK);
      if (!uid)
         return "Bad session";
      sql_string_t s = { };
      sql_sprintf(&s, "SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USER_ID_FIELD, uid);
      sql_free_result(res);
      res = sql_safe_query_store_s(&sql, &s);
      if (!sql_fetch_row(res))
         return "No user";
#else
      res = sql_safe_query_store_free(&sql, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_SESSION_FIELD, session));
      if (!sql_fetch_row(res))
         return "Not logged in";
#endif
      loginenv(res);
      return NULL;              // OK
   }
   const char *fail = check();
   if (res)
      sql_free_result(res);
#ifdef	CONFIG_HTTP_AUTH
   if (fail)
   {
      const char *auth = getenv("HTTP_AUTHORIZATION");
      if (auth && *auth)
      {                         // We have basic auth, decode base64 for username and password
         if (!getenv("HTTPS"))
            fail = "Must use https - your password may now be compromised";
         else
         {

            warnx("auth %s", auth);
         }
      }
   }
#endif
   sql_close(&sql);
   return fail;
}

void loginenv(SQL_RES * res)
{                               // Fill in login environment variables
   if (!res)
   {                            // Not logged in
      if (*CONFIG_ENV_USER_ID)
         unsetenv(CONFIG_ENV_USER_ID);
      return;
   }
   if (*CONFIG_ENV_USER_ID)
   {
      const char *uid = NULL;
      if (*CONFIG_DB_USER_ID_FIELD)
         uid = sql_col(res, CONFIG_DB_USER_ID_FIELD);
      else
         uid = sql_col(res, CONFIG_DB_USERNAME_FIELD);
      setenv(CONFIG_ENV_USER_ID, uid, 1);
   }



}
