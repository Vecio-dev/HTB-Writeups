# Stocker

## Summary

## General Enumeration
First thing let's scan for the open ports:
```
[vecio@vecio ~]$ nmap 10.10.11.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 19:09 CEST
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.46s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 29.17 seconds
```
We know that there are 2 services open: SSH service on port 22 and an HTTP server on the default port 80. We can check out the webb server, so we add the IP address to the /etc/hosts file:
```
# Static table lookup for hostnames.
# See hosts(5) for details.
127.0.0.1	localhost
::1		localhost
127.0.1.1	vecio.localdomain	vecio

10.10.11.196	stocker.htb
```
We can now access the web server on the browser using its domain or the IP address.

We notice that there is no real functionality we can exploit, so there must be something hidden.
We can guess that there might be a different part of the site on a specific subdomain: this technique is called `VHOST` (Virtual Host) which refers to the practice of running more than one website on a single machine, using subdomains like `a.example.com` and `b.example.com`.
In this case it will be a Name-based Virtual Host because the websites are hosted on the same IP, the webserver can differentiate to which website it has to send incoming requests through the HTTP `Host` header, which could be `example.com` or `a.example.com`.
So we can try to bruteforce using the top used subdomains to find an hidden website.
We can write our own tool: we just have to make a GET request to `http://(subdomain).stocker.htb`, getting the subdomain from a wordlist and checking the status code of the response.

Little tip: if you want to write your own script be aware that the website automatically redirects you to the main website giving the status code `301` when handling 404 pages, some libraries, like the nodejs `request`, will follow the redirect by default, which means that the response you receive will be the response from the redirected URL, not the original URL, giving the status code `200` even for wrong subdomains.

A good tool we can use to do that is [GoBuster](https://github.com/OJ/gobuster), which allow us, over a lot of other things, to search for working subdomains of a website, going over a wordlist, implementing the script which i mentioned above.
You can get the wordlist from the GitHub repository [SecLists](https://github.com/danielmiessler/SecLists).
Using GoBuster: `gobuster vhost -k --domain stocker.htb --append-domain -u http://10.10.11.196 -w ~/Wordlists/subdomains.txt`
```
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://10.10.11.196
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /home/vecio/Wordlists/subdomains-11m.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/03/28 19:35:53 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
```
We quite easly find the subdomain `dev` which redirects us to the `/login` route.
Let's add the new domain to the `/etc/hosts` file and see if we can find something to exploit in the `/login` route.
```
# Static table lookup for hostnames.
# See hosts(5) for details.
127.0.0.1	localhost
::1		localhost
127.0.1.1	vecio.localdomain	vecio

10.10.11.196	stocker.htb
10.10.11.196	dev.stocker.htb
```

Testing the new page, we find only a login form, which makes a POST request to the `/login` route with the data `username=admin&password=admin` being sent. If the request fails, as in this case, we get a login error.
We can assume that there could be some sort of database used that could be vulnerable to an injection.
We can find out using [Wappalyzer](https://www.wappalyzer.com/) that it is using the JS `Express` framework, so probably it is using a `NoSQL` database and this form may be vulnerable to a NoSQL Injection.

## Login Exploiting
Searching on the internet we can find this [cheatsheet](https://nullsweep.com/nosql-injection-cheatsheet/) and start testing, using BurpSuite, some common payloads to search for unwanted behaviour.
Since we know that it is using a NoSQL database, we want to test using JSON to format the data in the POST request, so we can change the request header `Content-Type` to be `application/json` and format the payload as JSON: `{"username":"admin", "password":"admin"}`.
We can now start testing some keywords and find that we can inject MongoDB `$ne` operator, so we can craft the following payload to bypass the authentication: `{"username": {"$ne":0}, "password": {"$ne":0}}` and get redirected to `/stock`.
The `$ne` operator stads for `not equal`, so we're passing a query where we ask for a user which username's not equal to 0 and password not equal to 0, this would end up in a success login and we get redirected logged in as an authenticated user.

Let's learn why this vulnerability is possible: looking at the source code of the website (which you can get after getting access to the server) we can find the method which manages the `/login` endpoint:
```js
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.redirect("/login?error=login-error");

  // TODO: Implement hashing

  const user = await mongoose.model("User").findOne({ username, password });

  if (!user) return res.redirect("/login?error=login-error");

  req.session.user = user.id;

  console.log(req.session);

  return res.redirect("/stock");
});
```
We can see that the server is getting the `username` and the `password` from the body of the request and passes those values to the mongodb `findOne()` method, without sanitizing them, which returns a document based on the queries that are passed, in this case username and password.
By injecting an object the query would become `findOne({ username: {$ne: 0}, password: ${$ne: 0} })` so it returns a user which username and password are not set to 0.

## Stock Enumeration
After we have successfully bypassed the authentication page we get redirected to the `/stock` route.
This page lets us add some items to a cart and proceed with the payment, which generates a check in pdf form.
The payment is done using a POST request to the endpoint `/api/order` with a json formatted body indluding a list of items that have been put in the cart, the response of the request includes an `orderId` which is used to create the route to view the pdf check `/api/po/64233a99566440aab8d5c56b`.
We can download the pdf file and use `Exiftool` to analyze it and find out that it is made using `Skia/PDF m108`.
Trying to edit the post request we can see that we can change the content of some fields and the result will be displayed in the pdf file, we can for example edit the `title` field of an item in the list and see that we get the edited title in the pdf result.
Doing a bit of research on the internet we find a [Server Side XSS (Dynamic PDF)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf) attack.
If a web page is creating a PDF using user controlled input, you can try to trick the bot that is creating the PDF into executing arbitrary JS code.
So, if the PDF creator bot finds some kind of HTML tags, it is going to interpret them, and you can abuse this behaviour to cause a Server XSS.

## Stock Exploitation
We can try to inject some payloads into the `title` field to see if the website is vulnerable.
If we inject this payload `<iframe src=file:///etc/passwd></iframe>` we can see in the returned pdf file the contents of the `/etc/passwd` file and find out the name of the user `angoose`.
Note that if the frame is too small to read the entire file, you can add some in-line css styling to make the frame bigger.
If can find the path of the project by injecting the following payload `<script> document.write(window.location) </script>` which returns `file:///var/www/dev/pos/64233e83a8e0cb4c2d3cfb83.html` we can now try to find the main file in the project subdirectories.
