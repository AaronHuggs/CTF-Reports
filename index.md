# 🏴‍☠️ Security Research & CTF Write-ups

This is where I document my **security research, CTF write-ups, and technical experiments**.  
Most of this comes from challenges on **HackTheBox, TryHackMe, and private labs**, but I'll also share **other security-related projects** over time.  

I'm always refining my approach, learning new techniques, and breaking things (in legal environments, of course).

---

## 🔍 CTF Write-ups

Here’s a collection of **detailed write-ups** on Capture The Flag challenges, including **enumeration, exploitation, and privilege escalation**.

### 🔥 HackTheBox Machines

- [Support](reports/hackthebox/support/) - Windows AD box, privilege escalation via Resource-Based Constrained Delegation
- [Active](reports/hackthebox/active/) - Windows AD box, privilege escalation via Kerberoasting
- [Soccer](reports/hackthebox/soccer/) - Linux box, file upload to RCE via Tiny File Manager, blind SQL injection over WebSocket, privilege escalation via doas+dstat
- [Heist](reports/hackthebox/heist/) - Windows box, user access via router config password reuse, privilege escalation via credential leak in log files
- [OpenAdmin](reports/hackthebox/openadmin/) – Linux box, remote code execution via OpenNetAdmin, password reuse to SSH, privilege escalation via sudo access to nano
- [Nest](reports/hackthebox/nest/) – Windows box, user access via decrypted VB-stored password, privilege escalation by decompiling executable to recover admin credentials
- [Curling](reports/hackthebox/curling/) – Linux box, Joomla admin RCE via template edit, password recovery through multi-stage decompression, privilege escalation by overwriting crontab via curl config
- More coming soon...

### 🕵️‍♂️ HackTheBox Sherlock Challenges

- Coming soon...

---

## 🛠 Security Projects

Beyond CTFs, I plan to explore **security tools, vulnerability research, and other offensive security topics**. Some areas I might dive into:

- **Custom Exploit Development**
- **Reverse Engineering & Binary Analysis**
- **Active Directory Attacks & Hardening**
- **Automated Recon & Enumeration Scripts**

Once I start building things worth sharing, they’ll be listed here.

---

## 📚 Methodology

For CTFs and real-world testing, I take a structured approach:

1. **Enumeration** - Identifying open services, hidden directories, and possible misconfigurations.  
2. **Exploitation** - Gaining access via vulnerabilities, weak credentials, or misconfigurations.  
3. **Privilege Escalation** - Finding paths to admin/root through misconfigurations or kernel exploits.  
4. **Post-Exploitation** - Extracting useful data, cleaning up, and documenting lessons learned.

Everything here is a **work in progress**, and that’s the point — breaking, learning, and improving.

---

💡 **Want to check out what I’ve been working on?** Dive into the write-ups or check back for new projects.
