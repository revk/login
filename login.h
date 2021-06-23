// Do a login

const char *login(SQL *,const char*session,const char *username,const char *password,const char *otp);
int password_ishash(const char *hash);
char *password_hash(const char *password);

