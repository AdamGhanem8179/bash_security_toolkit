#!/usr/bin/bash

LOG_DIR="logs"
mkdir -p "$LOG_DIR"   

log_message() {
    local logfile="$LOG_DIR/toolkit_$(date +%F).log"   
    echo "[$(date '+%F %T')] $1" | tee -a "$logfile"

}

#===============================================================================================================================================

validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

#===============================================================================================================================================

validate_hostname() {
    local hostname="$1"
    if [[ $hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

#===============================================================================================================================================

validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    else
        return 1
    fi
}

#===============================================================================================================================================

check_ports() {
    while true; do
        echo "Enter host (IP address or hostname): "
        read host
        if validate_ip "$host" || validate_hostname "$host"; then
            break
        else
            echo "Invalid host format. Please enter a valid IP address or hostname."
        fi
    done
    
    while true; do
        echo "Enter port number (1-65535): "
        read port
        if validate_port "$port"; then
            break
        else
            echo "Invalid port. Please enter a number between 1 and 65535."
        fi
    done
    
    echo "Checking port $port on $host in 5 seconds..."
    for i in {1..5}; do
        echo $i
        sleep 1
    done

    if timeout 5 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        echo "Port $port on $host is OPEN"
        log_message "Port check: $host:$port - OPEN"
    else
        echo "Port $port on $host is CLOSED or filtered"
        log_message "Port check: $host:$port - CLOSED/FILTERED"
    fi
}

#===============================================================================================================================================

check_server() {
    local server="$1"
    
    if ! validate_ip "$server" && ! validate_hostname "$server"; then
        log_message "Invalid server format: $server"
        echo "Error: Invalid server format"
        return 1
    fi
    
    if ping -c 1 -W 2 "$server" > /dev/null 2>&1; then
        log_message "Server $server is ALIVE"
        echo "Server $server is ALIVE"
        return 0
    else
        log_message "Server $server is DOWN"
        echo "Server $server is DOWN"
        return 1
    fi
}

#===============================================================================================================================================

bfdetec_ipban () {
    local logfile="${1:-/var/log/auth.log}"
    local banlist="./banned_ips.txt"  

    # here it extracts the ip from the failed attempts
    awk '/Failed password/ {
        if ($6 == "invalid") { ip = $12 } 
        else { ip = $11 }
        print ip
    }' "$logfile" | sort | uniq -c | while read count ip; do

        # here it checks if the ip is banned in the banlist
        if grep -qx "$ip" "$banlist"; then
            continue
        fi
        if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            continue  
        fi

       #here it banns the ip if it had more thasn 3 failed attempts
        if [ "$count" -ge 3 ]; then
            echo "Banning IP $ip due to $count failed login attempts"
            sudo iptables -A INPUT -s "$ip" -j DROP
            echo "$ip" >> "$banlist"
        fi
    done

}

#===============================================================================================================================================

print_bannedips() {
    local banlist="./banned_ips.txt"
     if [[ -f "$banlist" ]]; then
        echo "=== Banned IPs ===" 
        echo "File: $banlist"
        echo "Last modified: $(date -r "$banlist")"
        echo "----------------"
        cat "$banlist"
        echo "----------------"
        echo "Total banned IPs: $(wc -l < "$banlist")"
    else
        echo "No banned IPs file found at: $banlist"
    fi

}

#===============================================================================================================================================

unban_ip() {
    local banlist="./banned_ips.txt"
    #Here you can change the pass below to whatever you want
    local admin_password="123456"  
    
    echo -n "Enter admin password: "
    read -s password
    echo
    
    if [[ "$password" != "$admin_password" ]]; then
        echo "Incorrect password. Access denied."
        log_message "Failed unban attempt - incorrect password"
        return 1
    fi
    
    if [[ ! -f "$banlist" ]] || [[ ! -s "$banlist" ]]; then
        echo "No banned IPs found."
        return 1
    fi
    
    echo "=== Current Banned IPs ==="
    cat -n "$banlist"
    echo "=========================="
    
    while true; do
    echo -n "Enter IP to unban: "
    read ip_to_unban
    if validate_ip "$ip_to_unban"; then
        break
    else
        echo "Invalid IP format. Please enter a valid IP address."
    fi
done
    
    if ! grep -qx "$ip_to_unban" "$banlist"; then
        echo "IP $ip_to_unban is not in the ban list."
        return 1
    fi
    
    #Here itr emoves it from the iptable
    if sudo iptables -D INPUT -s "$ip_to_unban" -j DROP 2>/dev/null; then
        echo "Removed iptables rule for $ip_to_unban"
    else
        echo "No iptables rule found for $ip_to_unban (or already removed)"
    fi
    
    #Here it removes it from the banlist
    grep -vx "$ip_to_unban" "$banlist" > "${banlist}.tmp" && mv "${banlist}.tmp" "$banlist"
    
    echo "IP $ip_to_unban has been unbanned successfully."
    log_message "IP $ip_to_unban unbanned by admin"

}

#===============================================================================================================================================
# DISK AUDIT
disk_audit() {
    echo "=== DISK USAGE ==="
    df -h 2>/dev/null || { echo "Error: Unable to retrieve disk usage"; return; }
    echo
    echo "Top 5 largest directories in /:"
    du -h / --max-depth=1 2>/dev/null | sort -hr | head -5 || echo "Warning: Could not scan root directory"
    echo
    echo "Disk usage warnings (>90% full):"
    df -h | awk 'NR>1 && $5+0 > 90 {print "WARNING: " $6 " is " $5 " full"}' || echo "None"
    echo
}

#===============================================================================================================================================
# PROCESS AUDIT
process_audit() {
    echo "=== PROCESS AUDIT ==="
    echo "Top 10 CPU consuming processes:"
    ps aux --sort=-%cpu 2>/dev/null | head -11 || echo "Error: Unable to retrieve process info"
    echo
    echo "Top 10 Memory consuming processes:"
    ps aux --sort=-%mem 2>/dev/null | head -11 || echo "Error: Unable to retrieve process info"
    echo
    echo "Processes running as root:"
    ps -U root -u root u 2>/dev/null | head -11 || echo "Warning: Unable to list root processes"
    echo
    echo "Processes from temp directories (potential risk):"
    local temp_procs=$(ps aux 2>/dev/null | grep -E '(/tmp|/var/tmp)' | grep -v grep)
    [[ -n "$temp_procs" ]] && echo "$temp_procs" || echo "None found"
    echo
    echo "Suspicious processes (wget/curl/nc/python/perl/bash) in tmp/cache files:"
    local suspicious_procs=$(ps aux 2>/dev/null | grep -iE '(wget|curl|nc|netcat|python|perl|ruby|bash|sh).*\.(tmp|cache)' | grep -v grep)
    [[ -n "$suspicious_procs" ]] && echo "$suspicious_procs" || echo "None detected"
    echo
}

#===============================================================================================================================================
# NETWORK AUDIT
network_audit() {
    echo "=== NETWORK AUDIT ==="
    echo "Listening ports:"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn 2>/dev/null | grep LISTEN || echo "No listening ports found"
    else
        netstat -tulpn 2>/dev/null | grep LISTEN || echo "No listening ports found"
    fi
    echo
    echo "Established connections:"
    if command -v ss >/dev/null 2>&1; then
        ss -tupn 2>/dev/null | grep ESTAB | head -20 || echo "No established connections found"
    else
        netstat -tupn 2>/dev/null | grep ESTABLISHED | head -20 || echo "No established connections found"
    fi
    echo
    echo "Checking common backdoor ports (1234 4444 5555 6666 31337 12345 54321):"
    local backdoor_ports="1234 4444 5555 6666 31337 12345 54321"
    local found_backdoors=""
    for port in $backdoor_ports; do
        if ss -tuln 2>/dev/null | grep -q ":$port " || netstat -tuln 2>/dev/null | grep -q ":$port "; then
            found_backdoors="$found_backdoors $port"
        fi
    done
    [[ -n "$found_backdoors" ]] && echo "WARNING: Suspicious ports found:$found_backdoors" || echo "None detected"
    echo
}

#===============================================================================================================================================
# MEMORY AUDIT
memory_audit() {
    echo "=== MEMORY USAGE ==="
    free -h 2>/dev/null || { echo "Error: Unable to retrieve memory info"; return; }
    local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $mem_usage -gt 90 ]]; then
        echo "WARNING: Memory usage is ${mem_usage}% - critically high!"
    elif [[ $mem_usage -gt 80 ]]; then
        echo "WARNING: Memory usage is ${mem_usage}% - high"
    else
        echo "Memory usage: ${mem_usage}% - normal"
    fi
    echo
}

#===============================================================================================================================================
# LOAD AUDIT
load_audit() {
    echo "=== SYSTEM LOAD ==="
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    local cpu_cores=$(nproc 2>/dev/null || echo "1")
    if command -v bc >/dev/null 2>&1; then
        local load_ratio=$(echo "scale=2; $load_avg / $cpu_cores" | bc)
        if [[ $(echo "$load_ratio > 2.0" | bc) -eq 1 ]]; then
            echo "WARNING: Load average ($load_avg) is very high for $cpu_cores cores"
        elif [[ $(echo "$load_ratio > 1.0" | bc) -eq 1 ]]; then
            echo "WARNING: Load average ($load_avg) is high for $cpu_cores cores"
        else
            echo "Load average: $load_avg - normal"
        fi
    fi
    echo
}

#===============================================================================================================================================
# USER AUDIT
user_audit() {
    echo "=== USER SESSION INFO ==="
    echo "Currently logged in users:"
    who 2>/dev/null || echo "Unable to retrieve user sessions"
    echo
    echo "Recent login attempts (last 10):"
    last -n 10 2>/dev/null || echo "Unable to retrieve login history"
    echo
}

#===============================================================================================================================================
# SECURITY CHECKS
security_checks() {
    echo "=== SECURITY CHECKS ==="
    echo -n "World-writable files in /tmp: "
    find /tmp -type f -perm -002 2>/dev/null | wc -l
    echo -n "SUID files in system directories: "
    find /usr /bin /sbin -type f -perm -4000 2>/dev/null | wc -l
    echo
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo "SSH Security:"
        grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config && echo "  WARNING: Root login via SSH is enabled" || echo "  Root login via SSH: Properly configured"
        grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config && echo "  Password authentication enabled" || echo "  Password authentication: Disabled (good)"
    fi
    echo
    echo "Firewall status:"
    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null || echo "UFW: Status unknown"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --state 2>/dev/null || echo "Firewalld: Status unknown"
    elif command -v iptables >/dev/null 2>&1; then
        echo "Iptables rules: $(iptables -L 2>/dev/null | wc -l)"
    else
        echo "WARNING: No firewall detected"
    fi
    echo
}

#===============================================================================================================================================
# SYSTEM AUDIT MENU
system_audit_menu() {
    log_message "User entered system audit menu"
    while true; do
        echo "=== SYSTEM AUDIT MENU ==="
        echo "1. Disk Audit"
        echo "2. Process Audit"
        echo "3. Network Audit"
        echo "4. Memory Audit"
        echo "5. Load Audit"
        echo "6. User Audit"
        echo "7. Security Checks"
        echo "8. Run ALL Audits"
        echo "9. Back to Main Menu"
        echo "========================="
        echo -n "Choose an option (1-9): "
        read choice
        case $choice in
            1) disk_audit ;;
            2) process_audit ;;
            3) network_audit ;;
            4) memory_audit ;;
            5) load_audit ;;
            6) user_audit ;;
            7) security_checks ;;
            8) 
                disk_audit
                process_audit
                network_audit
                memory_audit
                load_audit
                user_audit
                security_checks
                ;;
            9) return ;;
            *) echo "Invalid choice" ;;
        esac
        echo
        echo "Press Enter to continue..."
        read
    done
}


#===============================================================================================================================================

#this is AI generated
show_help() {
    echo "=== SECURITY TOOLKIT HELP ==="
    echo "Available options:"
    echo "1. check_ports    - Check if a specific port is open on a host"
    echo "2. check_server   - Ping a server to check if it's alive"
    echo "3. bfdetec_ipban  - Detect brute force attempts and ban IPs"
    echo "4. print_bannedips - Display all currently banned IPs"
    echo "5. unban_ip       - Unban a specific IP address (requires admin password)"
    echo "6. system_audit   - Run comprehensive system security audit"
    echo "7. all            - Run all security checks (except unban_ip)"
    echo "8. help           - Show this help menu"
    echo "9. exit           - Exit the toolkit"
    echo "=============================="
    log_message "Help menu displayed"
}

#================================================================================================================================

main_menu() {
    log_message "Security toolkit started"
    
    while true; do
        echo
        echo "=== SECURITY TOOLKIT ==="
        echo "1. Check Ports"
        echo "2. Check Server"
        echo "3. Brute Force Detection & IP Ban"
        echo "4. Print Banned IPs"
        echo "5. Unban IP"
        echo "6. System Audit"
        echo "7. Run All"
        echo "8. Help"
        echo "9. Exit"
        echo "======================="
        echo -n "Choose an option (1-9): "
        read choice
        
        case $choice in
            1)
                log_message "User selected: Check Ports"
                check_ports
                ;;
            2)
                log_message "User selected: Check Server"
                echo -n "Enter server/IP to check: "
                read server
                check_server "$server"
                ;;
            3)
                log_message "User selected: Brute Force Detection"
                echo -n "Enter log file path (or press Enter for default /var/log/auth.log): "
                read logfile
                if [[ -z "$logfile" ]]; then
                    bfdetec_ipban
                else
                    bfdetec_ipban "$logfile"
                fi
                ;;
            4)
                log_message "User selected: Print Banned IPs"
                print_bannedips
                ;;
            5)
                log_message "User selected: Unban IP"
                unban_ip
                ;;
            6)
                
                log_message "User selected: System Audit"
                system_audit_menu
                ;;
            7|all|ALL)
                log_message "User selected: Run All Functions"
                echo "=== RUNNING ALL SECURITY FUNCTIONS ==="
                check_ports
                echo -n "Enter server/IP to check: "
                read server
                check_server "$server"
                bfdetec_ipban
                print_bannedips
                system_audit
                echo "=== ALL FUNCTIONS COMPLETED ==="
                ;;
            8|help|HELP)
                show_help
                ;;
            9|exit|EXIT|quit|QUIT)
                log_message "User exited security toolkit"
                echo "Exiting Security Toolkit. Stay secure!"
                exit 0
                ;;
            *)
                log_message "Invalid menu selection: $choice"
                echo "Invalid option. Please choose 1-9, or type 'help' for assistance."
                ;;
        esac
        
        echo
        echo "Press Enter to continue..."
        read
    done
}



#main
main_menu


