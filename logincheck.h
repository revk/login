
SQL_RES *find_session(SQL * sqlp, const char *session, int envstore);
const char *logincheck(const char *session);
void loginenv(SQL_RES *);
