[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json)](https://github.com/garrettfoster13/sccmhunter)
[![Black Hat USA Arsenal 2024](https://img.shields.io/badge/Black%20Hat%20USA%20Arsenal-2024-brightgreen?style=plastic)](https://www.blackhat.com/us-24/arsenal/schedule/index.html#sccmhunter-38141)
[![@garrfoster on Twitter](https://img.shields.io/twitter/follow/garrfoster?style=social)](https://twitter.com/garrfoster)




<p align="center">
    <img width="696" alt="image" src="https://github.com/user-attachments/assets/42f6572f-9df1-4229-a213-b02d9526f16d">
</p>

# SCCMHunter

SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain. Please checkout the [wiki](https://github.com/garrettfoster13/sccmhunter/wiki) for detailed usage.

### Please note
This tool was developed and tested in a lab environment. Your mileage may vary on performance. If you run into any problems please don't hesitate to open an issue.


## Installation
I strongly encourage using a python virtual environment for installation
```

git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
virtualenv --python=python3 .
source bin/activate
pip3 install -r requirements.txt
python3 sccmhunter.py -h
```

# References
Huge thanks to the below for all their research and hard work and 
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



