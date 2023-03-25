# Inject

### Info Gathering
First thing let's scan for the ports:
```bash
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

Looking around we see that the only functionality the web page has is to upload images to the server and then view them.
The main activity occurs in the POST request made to the `/upload` route to upload the image to the server and in the GET request made to the `/show_image?img=image.png` route.
Trying to find a vulnerability in the upload part is a rabbit hole, using BurpSuite to test the `/show_image?img=image.png` we find that the server actually takes the path from the http parameter `img` to choose what image to display.
Trying to make a get request to `/show_image?img=/` we get a list of files which are all the images files uploaded to the server.
![image](https://cdn.discordapp.com/attachments/717442721303887963/1089186119503069265/screenshot.png)
We can use this to see the system directories and files, we can do some enumeration about the web server: how it's made, what technologies does it use and the source code.
We can see that it is a Java WebServer, we can find the main source code at the path `/show_image?img=../java/com/example/WebApp/user/UserController.java` and we can see the method `getImage()` that manages the `/show_image` route and understand why this vulnerability is possible:

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
We can see that the HTTP `img` parameter is saved in the `name` variable, which is then combined to the `UPLOADED_FOLDER` class member in the `fileName` variable, so if we set the `img` parameter to `../`, the `fileName` variable would be:
```java
String fileName = "/var/www/WebApp/src/main/uploads/../";
```
Which is actually the whole `uploads` directory. The string is then converted into a `Path` object, which is then formatted into a UrlResource and returned as response.
