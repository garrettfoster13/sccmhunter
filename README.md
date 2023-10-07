<p align="center">
    <img width="316" alt="logo" src="https://user-images.githubusercontent.com/82191679/232257821-bd1a36d0-c5a0-47b8-8024-d98d67d98f68.png">
</p>

# SCCMHunter

SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain. The basic function of the tool is to query LDAP with the find module for potential SCCM related assets. This is achieved through ACL recon of objects created during the deployment process when extending the AD schema, as well as by performing queries for the keywords "SCCM" or "MECM". This list of targets is then profiled with the SMB module by checking the remarks for default shares required by assets configured with certain SCCM roles. Additionally, the module checks if the MSSQL service is running and if SMB signing is enforced on the endpoint. All of this helps paint a picture for potential attack paths in the environment. Once profiling is complete, the operator can target abusing client enrollment with the HTTP (@\_xpn\_) module accounts or use the MSSQL (@_mayyhem)  module to grab the necessary syntax for complete site server takeover. If a site server takeover is successful, the admin module is  available for post exploitation.

This tool was developed and tested in a lab environment. Your mileage may vary on performance. If you run into any problems please don't hesitate to open an issue.

## Table of Contents

- [SCCMHunter](#sccmhunter)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Help](#help)
- [Modules](#modules)
  - [Find](#find)
  - [SMB](#smb)
  - [Http](#http)
  - [Mssql](#mssql)
  - [Admin](#admin)
  - [Show](#show)
- [References](#references)



## Installation
```
git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
pip3 install -r requirements.txt
python3 sccmhunter.py
```

## Help

![v0002help](https://github.com/garrettfoster13/sccmhunter/assets/82191679/79a091f2-8d1d-4f1b-9ab0-b9635d8756f6)


# Modules

## Find

The find module queries LDAP for default ACLs created during extension of the AD schema during deployment. During installation, under the "System" container, the "System Management" container is created and the site server machine account is granted GenericAll permissions on the container object. Additionally, when configuring a server with the "Management Point" (MP) role in SCCM, the site server publishes this information in the "System Management" container in a mSSMSManagementPoint class object. The MP's dNSHostName attribute is stored here and is how clients will resolve available management points from AD. The last step is to simply query AD for acronyms related to SCCM or MECM based on administrators tendency use descriptive labels for related users, groups,  and systems. All potential site server hostnames are logged for use with the SMB and Http modules.

Here's an example of the results following running the find module:

![image](https://user-images.githubusercontent.com/82191679/236318577-54e6c8f0-613e-4965-9d87-9f7ad6b71902.png)


## SMB

The SMB module takes the results from Find and enumerates the remote hosts SMB shares, SMB signing status, and checks if the server is running MSSQL. During setup of particular roles in SCCM, such as the MP or distribution point (DP) roles, the remarks for default file shares disclose what the particular server's role is. This is useful due to requirements during deployment for the site server machine account to have local administrator rights for servers configured with the MP, DP, and SQL database roles and are vulnerable to relay attacks if SMB signing is disabled or not required. Through this profiling the operator can streamline the process of identifying this condition. Additionally, the SMB module checks for the existence of the "REMINST" file share found on DPs that indicate the use of PXEBoot. If found, this share is spidered for the presence of media variables files which can be leveraged to potentially obtain, sometimes privileged, domain users credentials as detailed by Christopher Panayi [here](https://github.com/MWR-CyberSec/PXEThief).

Here's an example of the results following running the smb module:

![image](https://user-images.githubusercontent.com/82191679/236318662-2f8e6a14-b899-40ea-b2d4-7e8e5f37b3f3.png)


## HTTP

The HTTP module also takes the results from Find and enumerates the remote hosts for SCCM enrollment web services. If found, the module leverages Adam Chester's [sccmwtf.py](https://github.com/xpn/sccmwtf) script to spoof client enrollment with provided machine account credentials or with the -auto flag attempts to create a new machine. More info on this attack can be found at Adam's blog [here](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)

Here's an example of the results following running the http module with the `-auto` flag:

![image](https://user-images.githubusercontent.com/82191679/236320371-b735e498-87a3-4b51-9a1b-f6cb36dfaf7f.png)

## MSSQL

The MSSQL module accepts arguments to provide the correct MSSQL query syntax to abuse the site server takeover attack discovered and detailed by Chris Thompson [here](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1). The hex-formatted SID of the user being granted "Full Administrator" permissions is queried and provided in the terminal. Once the first round of queries are complete, the operator is prompted to provide the minted administrator account’s AdminID and the second round of queries printed to the terminal.  

Here's an example of the results following running the mssql module:

![image](https://user-images.githubusercontent.com/82191679/236321626-404f1800-cb36-4449-80e9-10e65fad863e.png)

## Admin

The Admin module is a post site server takeover module intended to run post exploitation commands through the AdminService API. The module stores recovered users, devices, collections and device relationship data in a local SQLite database. Additional commands available include situation awareness commands to enumerate information on endpoints as well as performing arbitrary script execution on devices. All of my testing was performed in a controlled lab environment so your mileage may vary. If you run into any issues please open and issue and provide as much information as possible to explain the issue.

Here is an example of running the ipconfig situational awareness command.

<img width="1397" alt="Welcome" src="https://github.com/garrettfoster13/sccmhunter/assets/82191679/0285eaa3-d233-4d50-b6f1-b94f1c9cd541">


## Show

The show module is intended simply to present the stored CSVs generated during running the find and smb modules. They make for good screenshots :)

Here is an example of the show module showing users and groups related to SCCM:

![image](https://user-images.githubusercontent.com/82191679/236324826-a7d45dd9-af44-4034-9d30-d21173e6ff55.png)

# References
Thanks to the below for all their research and hard work
<br>
[@\_mayyhem](https://twitter.com/_Mayyhem)
<br>
[Coercing NTLM Authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
<br>
[SCCM Site Takeover via Automatic Client Push Installation](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)
<br>
<br>
[@TechBrandon](https://twitter.com/TechBrandon)
<br>
[Push Comes To Shove: exploring the attack surface of SCCM Client Push Accounts](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts)
<br>
[Push Comes To Shove: Bypassing Kerberos Authentication of SCCM Client Push Accounts.](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-bypassing-kerberos-authentication-of-sccm-client-push-accounts)
<br>
<br>
[@Raiona_ZA](https://twitter.com/Raiona_ZA)
<br>
[Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences)
<br>
<br>
[@\_xpn\_](https://twitter.com/_xpn_)
<br>
[Exploring SCCM by Unobfuscating Network Access Accounts](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
<br>
<br>
[@subat0mik](https://twitter.com/subat0mik)
<br>
[The Phantom Credentials of SCCM: Why the NAA Won’t Die](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
<br>
<br>
[@HackingDave](https://twitter.com/HackingDave)
<br>
[Owning One to Rule Them All](https://www.youtube.com/watch?v=Mz9Bg9KAKBs)



