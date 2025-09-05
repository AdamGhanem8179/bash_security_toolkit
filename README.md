🛡️ Sentinel – Bash Security Toolkit

A lightweight Bash-based security auditing and protection toolkit.
Sentinel helps system administrators monitor servers, detect brute-force login attempts, ban malicious IPs, and audit system health — all from a single script.

By default, Sentinel is run manually (you launch it when needed).
However, it can be easily switched to automatic monitoring by wrapping parts of the script (like brute force detection) inside a while true loop and running it as a background service.
while true; do
    ./sentinel.sh
    sleep 300  #here this means it executes each 300 seconds
done

in the logsd everything is stored with a timestamp you can check everything there each command used and at what time 

requirments are only linux system with bash

regarding the password i set it to 123456 u can easily switch it to the sudo password or whatever password you want note (it isnt safe to stay like this in the code)
ande for banning or unbanning it requires sudo privileges 

Features 
🔍 Port & Server Checks – validate open ports and ping servers.

🚫 Brute Force Detection – scan authentication logs and automatically ban abusive IPs using iptables.

📋 Banlist Management – view and unban IPs with password protection.

📊 System Audits – disk usage, processes, network connections, memory, load, users, and security checks.

🛠️ Modular Menu System – easy-to-navigate CLI menu.

📜 Logging – all actions saved with timestamps.


its free to use u can clone it and share ir edit it its all up to you 

to use it after having the req u open the terminal and type 
chmod +x itsname
./itsname
