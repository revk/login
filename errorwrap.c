// Simple error wrapper
// (c) Adrian Kennard 2020

#include "config.h"
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include "errorwrap.h"

void errorwrap_opts(errorwrap_t o)
{
   if (isatty(2) && !o.done)
      return;                   // console, do not wrap
   if (!o.name)
      o.name = getenv("SCRIPT_NAME") ? : "";
   if (!o.ip)
      o.ip = getenv("REMOTE_ADDR") ? : "";
   int pipefd[2];
   if (pipe(pipefd) == -1)
      err(1, "pipe");
   int pid = fork();
   if (pid < 0)
      err(1, "fork");
   if (pid)
   {                            /* parent, wait for child */
      struct timeval tv;
      struct timezone tz;
      struct tm tm;
      char d[21];
      char *buf = NULL;
      size_t l;
      FILE *out = open_memstream(&buf, &l);
      {
         if (o.name && *o.name == '/')
            o.name++;
         const char *scriptend = strrchr(o.name, '.');
         if (!scriptend || strcmp(scriptend, ".cgi"))
            scriptend = o.name + strlen(o.name);
         gettimeofday(&tv, &tz);
         localtime_r(&tv.tv_sec, &tm);
         strftime(d, sizeof(d), "%F %T", &tm);
         fprintf(out, "%s.%06ld: %.*s\t%s\n", d, tv.tv_usec, (int) (scriptend - o.name), o.name, o.ip);
      }
      close(pipefd[1]);
      size_t t = 0;
      char eol = 0;
      {                         // Get stderr
         char temp[16 * 1024];
         while ((l = read(pipefd[0], temp, sizeof(temp))) > 0)
         {
            if (eol && o.timestamp)
            {
               gettimeofday(&tv, &tz);
               localtime_r(&tv.tv_sec, &tm);
               strftime(d, sizeof(d), "%F %T", &tm);
               fprintf(out, "%s.%06ld:", d, tv.tv_usec);
            }
            fwrite(temp, l, 1, out);
            eol = (temp[l - 1] < ' ');
         }
         t += l;
      }
      close(pipefd[0]);
      int wstatus = 0;
      waitpid(pid, &wstatus, 0);
      if (!WIFEXITED(wstatus))
         t += fprintf(out, "Bad exit\n");
      else if (o.exitzero && WEXITSTATUS(wstatus))
         t += fprintf(out, "Exit non zero (%d)", WEXITSTATUS(wstatus));
      if (t)
         fprintf(out, "\n");
      fclose(out);
      if (t && write(2, buf, l) < 0)
         errx(1, "WTF");        // Write in one go
      free(buf);
      if (o.done)
         o.done();
      exit(0);
   }
   // Child - carry on
   close(pipefd[0]);
   // Redirect stderr to the pipe
   if (dup2(pipefd[1], 2) == -1)
      err(1, "Failed to dup2 stdout to the pipe");
}
