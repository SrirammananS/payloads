# FILE UPLOAD

## Stored XSS :
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
