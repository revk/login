# login

This is a generic set of tools that allow web CGI scripts to work with a login (managed by sql back end).

The tools have to cater for a lot of possible usage scenarios, and so uses Kconfig (`make menuconfig`) to define the environment for usage. This then makes the individual tools very simple as they do not need a myriad of options.

## `envcgi` wrapper

There are wrapper tools, the main one being a generic `envcgi` tool which you use in a script. E.g. if your script normally started with (old school!) `#!/bin/csh` you can *wrap* it by using `#!envcgi /bin/csh` instead, though typically it would be something like `#!../login/envcgi /bin/csh` if you have `login` checked out a directory above.

The effect of this is to put all form posted fields in environment variables (with a few exceptions, like `$USER`) making it easy for your script to process a form. This works for `GET` and `POST` and even works for posting files (creates a temporary file which is deleted after the script runs).

The easiest way to understand this is try it, printing the environment when you send various types of form data, but mostly it is pretty obvious.

`envcgi` and related tools set a session tracking cookie used to manage login. Whilst a session cookie is normally used, it is possible to also allow http authentication if the header is configured in apache, and so allow per page access login with correct password (e.g. to use with curl).

The wrapper can also perform form security checks - providing an environment variable to include in a form that is then checked when the form is received.

## Logged in wrapper

There are variations of `envcgi` for login handling. These are `loggedin` and `logincheck` and used in the same way, e.g. `#!../login/loggedin /bin/csh`

The `loggedin` tool will not run the script if not logged in, but instead redirect to the configured login page.

The `logincheck` tool will run the script even if not logged in.

If logged in then a number of extra environment variables are set. You need to avoid these variables in forms you use, obviously, to avoid clashes. The actual variables set are configurable in the build. One variable is the unique user ID from your user table, usually `$USER_ID` which is explicitly *unset* if you are not logged in, and so can be used to check if login worked or not.

Obviously these also pass any form data as environment variables in the same way as `envcgi`.

Normally these wrappers are followed by the shell you are using, but you can add some additional arguments before the shell...

- `--no-cookie`	Don't set the session cookie
- `--no-post`	Don't process POST, allows the cgi to process the posted data if needed
- `--no-options`	Don't answer OPTIONS, allows the cgi to handle them
- `--no-nocache`	Don't send a no-cache header. Normally this is automatically sent
- `--no-http-auth` Don't allow HTTP authorization (unsets the header)
- `--all-file`	Treat all fields as if they were a file post

## Tools

There are also tools that the scripts can use.

`dologin` will take environment variables (i.e. set by `envcgi` or `logincheck`) and perform a login. Normally this is `$USERNAME` and `$PASSWORD` but the fields can be configured. It returns a status 0 if the login worked. **This writes to stdout with error reason if login fails, so should be caputured, or use `--silent`**

Note that `dologin --redirect` can be used directly from script wrapped under `logincheck` and it will redirect to home or login page with error based on login result.

`dologout` will logout. It returns status 0 if was logged in.

Note that `dologout --redirect` can be used directly from script wrapped under `logincheck` and it will redirect to login page.

`changepassword` will take environment variables (i.e. set by `envcgi` or `logincheck`) and perform a password change. Normally this is `$OLDPASSWORD` and `$NEWPASSWORD`. It returns a status 0 if the password was changed. You have to be logged in for this to work. **This writes to stdout with error reason if change fails, so should be caputured, or use `--silent`**

`password` suggests a random password. There are arguments for length, entropy, etc, but these are usually set by `menuconfig`.

## Passwords

The system stores passwords in a hash, usually in a `text` field called `pass` in a database. The system understands a number of password hash formats including mysql `password()` hashs. The supported hashes are configurable. When a user logs in correctly the password is updated if necessary to the latest password format used - currently `argon2`. This helps ensure you are using current best practice password hashes.

## OTP

One time passwords may be added later, but at present the system works only on passwords. This will be a configurable feature, for backwards compatibility.

## Database

The database is used to track the logged in user - the database and table and connection details are all configurable. A user table has some unique login field and a password hash field, which are configurable. The user table can hold the web session for single login (i.e. login somewhere else clears previous login), or a separate session table can be used - again, configurable.

The user fields in the user table are normally provided to the environment, but these can be selected and prefixed and upper cased, based on configuration.

The session expiry is a configurable setting and can be set never to expire if you prefer.

## Library

Library versions of `login`, `logout`, `logincheck`, `password`, `changepassword` are provided to link in to your own code.
