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
