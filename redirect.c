// Some misc tools

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void sendredirect(const char *page, const char *fail)
{
   const char *v;
   printf("Location: ");
   if (*CONFIG_ENVCGI_SERVER && (v = getenv(CONFIG_ENVCGI_SERVER)))
      printf("%s", v);
#ifdef  CONFIG_ENV_DB_FROM_URL
   if (*CONFIG_ENV_DB && (v = getenv(CONFIG_ENV_DB)) && *v)
      printf("%s/", v);
#endif
   const char *back = NULL;
   if (*CONFIG_ENV_BACK)
      back = getenv(CONFIG_ENV_BACK);
   if (!back)
      back = getenv("REQUEST_URI");
   if (back && !strcmp(back, CONFIG_PAGE_LOGIN))
      back = NULL;
   if (!page)
      page = (fail ? CONFIG_PAGE_LOGIN : back ? : CONFIG_PAGE_HOME);
   v = page;
   if (*v == '/')
      v++;
   printf("%s", v);
   void add(const char *tag, const char *val) {
      if (!tag || !*tag || !val || !*val)
         return;
      printf(v ? "?" : "&");
      v = NULL;
      printf("%s=", tag);
      while (*val)
      {
         if (*val == ' ')
            putchar('+');
         else if (*val < ' ' || strchr(";?:@^=+$,/", *val))
            printf("%%%02d", *val);
         else
            putchar(*val);
         val++;
      }
   }
   add(CONFIG_ENV_BACK, back);
   add(CONFIG_ENV_FAIL, fail);
   printf("\n\r\n\r");
   fflush(stdout);
}
