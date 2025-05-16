# FILE UPLOAD

## Arbitary file uploads
https://enterprise.hackthebox.com/academy-lab/30000/2125/modules/136/1291

### Stored XSS :
- web application allows us to upload HTML files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines.
- Web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the Comment or Artist parameters, as follows:
  
    ```bash
    $ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
    $ exiftool HTB.jpg
    ...SNIP...
    Comment                         :  "><img src=1 onerror=alert(window.origin)>
    ```
    
    the Comment parameter was updated to our XSS payload. When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack.
  
- If we change the image's MIME-Type to text/html, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.
  
- XSS attacks can also be carried with SVG images, along with several other attacks. Scalable Vector Graphics (SVG) images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload.
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
        <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
        <script type="text/javascript">alert(window.origin);</script>
    </svg>
    ```
    Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

### XEE:

- With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server.
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
  Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (/etc/passwd) printed on the page or shown in the page source.

- To use XXE to read source code in PHP web applications
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
  <svg>&xxe;</svg>
  ```
  Once the SVG image is displayed, we should get the base64 encoded content of index.php, which we can decode to read the source code.

- Using XML data is not unique to SVG images, as it is also utilized by many types of documents, like PDF, Word Documents, PowerPoint Documents, among many others. All of these documents include XML data within them to specify their format and structure. Suppose a web application used a document viewer that is vulnerable to XXE and allowed uploading any of these documents. In that case, we may also modify their XML data to include the malicious XXE elements, and we would be able to carry a blind XXE attack on the back-end web server.
- Another similar attack that is also achievable through these file types is an SSRF attack. We may utilize the XXE vulnerability to enumerate the internally available services or even call private APIs to perform private actions. For more about SSRF, you may refer to the Server-side Attacks module.

### DoS
- **Decompression Bomb** : If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.
- **Pixel Flood** : We can create any JPG image file with any image size (e.g. 500x500), and then manually modify its compression data to say it has a size of (0xffff x 0xffff), which results in an image with a perceived size of 4 Gigapixels. When the web application attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.
- If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. ../../../etc/passwd), which may also cause the server to crash. 

## Other 
https://enterprise.hackthebox.com/academy-lab/30000/2125/modules/136/1292

### Injection
- OS Command in file names:
  - ```file$(whoami).jpg```
  - ```file`whoami`.jpg```
  - ```file.jpg||whoami```
- XSS PAyload:
  - ```<script>alert(window.origin);</script>```
- SQL Query:
    - ```file';select+sleep(5);--.jpg```
 
### Upload Directory Disclosure
- fuzzing to look for the uploads directory or even use other vulnerabilities (e.g., LFI/XXE) to find where the uploaded files are by reading the web applications source code
- Error Message
  - uploading a file with a name that already exists
  - sending two identical requests simultaneously
  - uploading a file with an overly long name (e.g., 5,000 characters)
- Windows-Specific techniques
  - attack is using reserved characters, such as (|, <, >, *, or ?), which are usually reserved for special uses like wildcards.
  - Windows reserved names for the uploaded file name, like (CON, COM1, LPT1, or NUL), which may also cause an error as the web application will not be allowed to write a file with this name.
  - utilize the Windows 8.3 Filename Convention to overwrite existing files or refer to files that do not exist
  - file called (hackthebox.txt) we can use (HAC\~1.TXT) or (HAC\~2.TXT), where the digit represents the order of the matching files that start with (HAC). As Windows still supports this convention, we can write a file called (e.g. WEB~.CONF) to overwrite the web.conf file.

    
