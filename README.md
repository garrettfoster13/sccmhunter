<p align="center">
    <img width="316" alt="logo" src="https://user-images.githubusercontent.com/82191679/232257821-bd1a36d0-c5a0-47b8-8024-d98d67d98f68.png">
</p>

# SCCMHunter

SCCMHunter is a post-ex tool to identify, profile, and attack SCCM related assets in an Active Directory domain. The basic function of the tool is to query LDAP with the find module for potential SCCM related assets through ACL recon of objects generated when extending the AD schema during deployment and by simply querying for the strings "SCCM" or "MECM". This list of targets is then profiled with the SMB module by checking the remarks for default shares required by assets configured with certain SCCM roles, if the MSSQL service is running, and if SMB signing is enforced on the endpoint. All of this helps paint a picture for potential attack paths in the environment. Once profiling is complete, the consultant can target abusing client enrollment with the HTTP (@\_xpn\_) module accounts or use the MSSQL (@_mayyhem)  module to grab the necessary syntax for complete site server takeover. If a site server takeover is successful, the admin and pivot modules are available for further information gathering and abuse.

This tool was developed and tested in a lab environment. Your mileage may vary on performance. If you run into any problems please don't hestiate to open an issue. 

Check out the wiki for more detailed usage.

## Installation
```
git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
pip3 install .
```

## Basic Usage

![menu](https://user-images.githubusercontent.com/82191679/235783472-2c06a8c6-bc23-4f07-97c2-4e358d947d7d.png)
