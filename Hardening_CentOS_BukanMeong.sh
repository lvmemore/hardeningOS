#!/bin/bash
:

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

success=0
fail=0

yum update -y && yum install wget -y

###########################################################################################################################

##Category 1.5 Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE}1.5 Initial Setup - Additional Process Hardening${NC}"

#Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"

#Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IP forwarding is disabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 3.2 Network Configuration - Network Parameters (Host and Router)
echo
echo -e "${BLUE}3.2 Network Configuration - Network Parameters (Host and Router)${NC}"

#Ensure TCP SYN Cookies is enabled
echo
echo -e "${RED}3.2.8${NC} Ensure TCP SYN Cookies is enabled"
egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
success=$((success + 1))
echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"

############################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)
echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"

#Ensure auditd service is enabled
echo
echo -e "${RED}4.1.2${NC} Ensure auditd service is enabled"
systemctl start auditd && systemctl enable auditd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd service is enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

#Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
systemctl enable rsyslog
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog Service is enabled"
  fail=$((fail + 1))
fi

#Ensure rsyslog default file permissions configured
echo
echo -e "${RED}4.2.1.3${NC} Ensure rsyslog default file permissions configured"
grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
success=$((success + 1))
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"

###########################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

#Ensure SSH Protocol is set to 2
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
  fail=$((fail + 1))
fi

#Ensure SSH LogLevel is set to INFO
echo
echo -e "${RED}5.2.3${NC} Ensure SSH LogLevel is set to INFO"
egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config || echo "LogLevel INFO" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is set to INFO"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LogLevel is set to INFO"
  fail=$((fail + 1))
fi


#Ensure SSH MaxAuthTries is set to 4 or less
echo
echo -e "${RED}5.2.5${NC} Ensure SSH MaxAuthTries is set to 4 or less"
egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  fail=$((fail + 1))
fi

#Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
  fail=$((fail + 1))
fi

#Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
  fail=$((fail + 1))
fi

#Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  fail=$((fail + 1))
fi

#Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disabled"
egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disabled"
  fail=$((fail + 1))
fi

#Ensure SSH warning banner is configured
echo
echo -e "${RED}5.2.15${NC} Ensure SSH warning banner is configured"
egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Banner\s+\S+(\s*#.*)?\s*$/\1Banner /etc/issue.net\2/" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH warning banner is configured"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

#Ensure cron daemon is enabled
echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
systemctl enable crond
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"

#Ensure password hashing algorithm is SHA-512
echo
echo -e "${RED}5.3.4${NC} Ensure password hashing algorithm is SHA-512"
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/system-auth
echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
success=$((success + 1))

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

#Ensure password expiration is 365 days or less
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 365 days or less"
egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"
success=$((success + 1))

#Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
success=$((success + 1))

#Ensure password expiration warning days is 7 or more
echo
echo -e "${RED}5.4.1.3${NC} Ensure password expiration warning days is 7 or more"
egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --warndays 7
echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
success=$((success + 1))

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

#Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd && chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/shadow are configured
echo
echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/shadow are configured"
chown root:root /etc/shadow && chmod 000 /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group && chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

echo
echo -e "${GREEN}Remediation script for CentOS Linux 7 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################
