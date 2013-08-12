#!/bin/bash

mkdir -p /root/NSI-BacFile

##############################
#关闭非必要服务
##############################

/etc/init.d/postfix stop;
/etc/init.d/iptables stop;
/etc/init.d/ip6tables stop;
chkconfig postfix off;
chkconfig iptables off;
chkconfig ip6tables off;
chkconfig ntpd on;
chkconfig --list;

cp -rpv /etc/selinux/config /root/NSI-BacFile/selinux-config

SELINUX_STATUS=`egrep ^SELINUX= /etc/selinux/config | awk -F "=" '{print $2}'`;
echo "Selinux status:${SELINUX_STATUS}";
if [[ "$SELINUX_STATUS" != "disabled" ]]
then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config;
        SELINUX_STATUS=`egrep ^SELINUX= /etc/selinux/config | awk -F "=" '{print $2}'`;
        if [[ "$SELINUX_STATUS" == "disabled" ]]
        then
                echo "Selinux is disabled,please reboot the system after other process.";
        else
                echo "Disable Selinux faild,please do it manually.";
        fi
fi

##############################

##############################
#修改主机名
##############################

cp -rpv /etc/sysconfig/network /root/NSI-BacFile/bak-network

IDC_DOMAIN="bjyz.dajie-inc.com";

echo "Please enter new host name in form XXX-XXX (use Ctrl+u to delete input)";
read -p "New host name:" NEW_HOST_NAME;
sed -i "s/^HOSTNAME=.*/HOSTNAME=${NEW_HOST_NAME}.${IDC_DOMAIN}/" /etc/sysconfig/network
HOST_NAME=`echo "${NEW_HOST_NAME}.${IDC_DOMAIN}"`;
hostname ${HOST_NAME};


##############################

##############################
#添加相关用户
##############################

NEW_USERS="webmaster zabbix";

for ADD_USER in ${NEW_USERS}
do
        OLD_USER=`egrep ^$ADD_USER /etc/passwd`;
        if [[ "${OLD_USER}" = '' ]]
        then
                echo "Add user: ${ADD_USER}";
                useradd ${ADD_USER};
        else
                echo "${ADD_USER} is exist,no need to add it."
        fi
done;

##############################

##############################
#配置IP地址、DNS、网关。
##############################

NEW_NAMESERVER1="10.10.67.210";
NEW_NAMESERVER2="10.10.67.220";
echo "${NEW_HOST_NAME}";
IP1=`echo "${NEW_HOST_NAME}" | awk -F "-" '{print $1}'`;
IP2=`echo "${NEW_HOST_NAME}" | awk -F "-" '{print $2}'`;

#echo "Please enter the IP address(use Ctrl+u to delete input):";
#read -p "New IP address:" NEW_IPADDR;
#echo "Please enter the Netmask(use Ctrl+u to delete input):";
#read -p "Netmask:" NEW_NETMASK;
#echo "Please enter the Gateway(use Ctrl+u to delete input):";
#read -p "Gateway:" NEW_GATEWAY;
#echo $NEW_IPADDR--$NEW_NETMASK--$NEW_GATEWAY;

NEW_IPADDR=`echo "10.10.$IP1.$IP2"`;
NEW_NETMASK="255.255.252.0";
NEW_GATEWAY="10.10.67.253";

VPS_INTERFACE="/etc/sysconfig/network-scripts/ifcfg-eth0";
PHY_INTERFACE="/etc/sysconfig/network-scripts/ifcfg-em1";

PING_CHECK=`ping -c 3 ${NEW_IPADDR} | grep time=`;
echo ${PING_CHECK};
if [[ -n "${PING_CHECK}" ]]
then
        echo "The IP is in using!!!"
        exit;
fi

if [[ -e ${PHY_INTERFACE} ]]
then
        cp -rpv $PHY_INTERFACE /root/NSI-BacFile/bak-ifcfg-em1;
        cp -rpv /etc/sysconfig/network /root/NSI-BacFile/bak-network;
        echo "The net interface of this system is em1";
        sed -i 's/BOOTPROTO=.*/BOOTPROTO=none/' $PHY_INTERFACE;
        echo "Add $NEW_IPADDR into the config file...";
        echo "IPADDR=$NEW_IPADDR" >> $PHY_INTERFACE;
        echo "Add $NEW_NETMASK into the config file...";
        echo "NETMASK=$NEW_NETMASK">> $PHY_INTERFACE;
        echo "Add $NEW_GATEWAY into the config file...";
        echo "GATEWAY=$NEW_GATEWAY" >> /etc/sysconfig/network;
        echo "The new interface config file is:";
        cat $PHY_INTERFACE;
        echo "The new Gateway and hostname is:";
        cat /etc/sysconfig/network;
else
        if [[ -e ${VPS_INTERFACE} ]]
        then
                cp -rpv $VPS_INTERFACE /root/NSI-BacFile/bak-ifcfg-eth0;
                cp -v /etc/sysconfig/network /root/NSI-BacFile/bak-network;
                echo "The net interface of this system is eth0";
                sed -i 's/BOOTPROTO=.*/BOOTPROTO=none/' $VPS_INTERFACE;
                echo "Add $NEW_IPADDR into the config file...";
                echo "IPADDR=$NEW_IPADDR" >> $VPS_INTERFACE;
                echo "Add $NEW_NETMASK into the config file...";
                echo "NETMASK=$NEW_NETMASK" >> $VPS_INTERFACE;
                echo "Add $NEW_GATEWAY into the config file...";
                echo "GATEWAY=$NEW_GATEWAY" >> /etc/sysconfig/network;
                echo "The new interface config file is:";
                cat $VPS_INTERFACE;
                echo "The new Gateway and hostname is:";
                cat /etc/sysconfig/network;
        fi
fi

cp -v /etc/resolv.conf /root/NSI-BacFile/bak-resolv.conf
echo "search $IDC_DOMAIN" > /etc/resolv.conf;
echo "nameserver $NEW_NAMESERVER1" >> /etc/resolv.conf;
echo "nameserver $NEW_NAMESERVER2" >> /etc/resolv.conf;

cp -v /etc/sysctl.conf /root/NSI-BacFile/bak-sysctl.conf
echo "
#Dajie Disable ipv6 add by Dajie-NSI.
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
" >> /etc/sysctl.conf

##############################

##############################
#初始化ROOT目录
##############################

NEW_DIR="/ROOT/server /ROOT/logs /ROOT/scripts /ROOT/www /ROOT/project /ROOT/install /ROOT/backup";

if [[ -d /ROOT ]]
then
        for MAKE_DIR in ${NEW_DIR}
        do
                if [[ ! -d ${MAKE_DIR} ]]
                then
                        echo "Making dir: ${MAKE_DIR}";
                        mkdir -p ${MAKE_DIR};
                else
                        echo "${MAKE_DIR} is already here,no need to make it.";
                fi
        done
else
        echo "There is no /ROOT,let's make it and go on";
        mkdir /ROOT;
        for MAKE_DIR in ${NEW_DIR}
        do
                if [[ ! -d ${MAKE_DIR} ]]
                then
                        echo "Making dir: ${MAKE_DIR}";
                        mkdir -p ${MAKE_DIR};
                else
                        echo "${MAKE_DIR} is already here,no need to make it.";
                fi
        done
fi

chown -R webmaster:webmaster /ROOT

##############################

##############################
#修改rsyslog，ulimte
##############################

cp -rpv /etc/security/limits.conf /root/NSI-BacFile/bak-limits.conf;
cp -rpv /etc/security/limits.d/90-nproc.conf /root/NSI-BacFile/bak-limits.d-90-nproc.conf;

wget http://10.10.67.250/nsi/90-nproc.conf -O /etc/security/limits.d/90-nproc.conf

ULIMITS_TEST=`egrep '^webmaster       ....' /etc/security/limits.conf`;
if [[ "${ULIMITS_TEST}" = '' ]]
then
        echo "Change the ulimits of webmaster...";
        sed -i '/# End of file/i\*       soft    nofile          65535' /etc/security/limits.conf
        sed -i '/# End of file/i\*       hard    nofile          65535' /etc/security/limits.conf
        egrep '^webmaster       ....' /etc/security/limits.conf;
else
        echo "The ulimits of webmaster is:";
        echo "${ULIMITS_TEST}";
fi

cp -rpv /etc/rsyslog.conf /root/NSI-BacFile/bak-rsyslog.conf
sed -i '/#kern/a\kern.*                \/var\/log\/kern' /etc/rsyslog.conf
sed -i 's/cron\.none/cron.none;local6.none/' /etc/rsyslog.conf 
sed -i '/local7/a\local6.* @@log.op.dajie-inc.com' /etc/rsyslog.conf; 

if grep ^\$WorkDirectory /etc/rsyslog.conf
then
        sed -i 's/^\$WorkDirectory.*/\$WorkDirectory \/var\/spool\/rsyslog/' /etc/rsyslog.conf;
else
        sed -i '$a\$WorkDirectory \/var\/spool\/rsyslog' /etc/rsyslog.conf;
fi

if grep ^\$ActionQueueFileName /etc/rsyslog.conf
then
        sed -i 's/^\$ActionQueueFileName.*/\$ActionQueueFileName fwdRule1/' /etc/rsyslog.conf;
else
        sed -i '$a\$ActionQueueFileName fwdRule1' /etc/rsyslog.conf;
fi


if grep ^\$ActionQueueMaxDiskSpace /etc/rsyslog.conf
then 
        sed -i 's/^\$ActionQueueMaxDiskSpace.*/\$ActionQueueMaxDiskSpace 1g/' /etc/rsyslog.conf;
else
        sed -i '$a\$ActionQueueMaxDiskSpace 1g' /etc/rsyslog.conf;
fi

if grep ^\$ActionQueueSaveOnShutdown /etc/rsyslog.conf
then
        sed -i 's/^\$ActionQueueSaveOnShutdown.*/\$ActionQueueSaveOnShutdown on/' /etc/rsyslog.conf;
else
        sed -i '$a\$ActionQueueSaveOnShutdown on' /etc/rsyslog.conf;
fi

if grep ^\$ActionQueueType /etc/rsyslog.conf
then
        sed -i 's/^\$ActionQueueType.*/\$ActionQueueType LinkedList/' /etc/rsyslog.conf;
else
        sed -i '$a\$ActionQueueType LinkedList' /etc/rsyslog.conf;
fi

if grep ^\$ActionResumeRetryCount /etc/rsyslog.conf
then
        sed -i 's/^\$ActionResumeRetryCount.*/\$ActionResumeRetryCount -1/' /etc/rsyslog.conf;
else
        sed -i '$a\$ActionResumeRetryCount -1' /etc/rsyslog.conf;
fi

##############################

##############################
#修改yum源
##############################

NEW_YUM_REPO="http://yum.op.dajie-inc.com/centos/\$releasever/os/\$basearch/";
NEW_YUM_UPDATE="http://yum.op.dajie-inc.com/centos/\$releasever/updates/\$basearch/";
NEW_YUM_EPEL="http://yum.op.dajie-inc.com/centos/\$releasever/epel/\$releasever/\$basearch/";
NEW_YUM_DJRPM="http://yum.op.dajie-inc.com/centos/\$releasever/dajie-rpms/\$basearch/";

echo "Backup the config of default repos...";
mkdir -p /root/NSI-BacFile/bak-repos;
mv /etc/yum.repos.d/* /root/NSI-BacFile/bak-repos;
echo "[base]
name=CentOS-\$releasever - Base
baseurl=${NEW_YUM_REPO}
gpgcheck=0
pkgpolicy=newest

" >> /etc/yum.repos.d/CentOS-Base.repo;

echo "[updates]
name=CentOS-\$releasever - Updates
baseurl=${NEW_YUM_UPDATE}
gpgcheck=0
pkgpolicy=newest

" >> /etc/yum.repos.d/CentOS-Base.repo;

echo "[epel]
name=CentOS-$releasever - epel
baseurl=${NEW_YUM_EPEL}
gpgcheck=0
pkgpolicy=newest

" >> /etc/yum.repos.d/CentOS-Base.repo;

echo "[dajie-rpms]
name=CentOS-$releasever - dajie-rpms
baseurl=${NEW_YUM_DJRPM}
gpgcheck=0
pkgpolicy=newest

" >> /etc/yum.repos.d/CentOS-Base.repo;


##############################

##############################
#修改ntp服务器
##############################

NTP1="ntp1.op.dajie-inc.com";
NTP2="ntp2.op.dajie-inc.com";

echo "Backup ntp.conf .....";
cp -rpv /etc/ntp.conf /root/NSI-BacFile/bak-ntp.conf
sed -i 's/server.*//' /etc/ntp.conf;
echo "server $NTP1" >> /etc/ntp.conf;
echo "server $NTP2" >> /etc/ntp.conf;
 

##############################

##############################
#kerberos配置
##############################

echo "Backup the krb5.conf......";
mv /etc/krb5.conf /root/NSI-BacFile/bak-krb5.conf
mkdir -p /ROOT/logs/kdc/
wget http://10.10.67.250/nsi/krb5.conf -O /etc/krb5.conf
wget http://10.10.67.250/nsi/k5login -O /root/.k5login
touch /home/webmaster/.k5login
chmod 700 /root/.k5login
chmod 700 /home/webmaster/.k5login

cp -rpv /etc/ssh/sshd_config /root/NSI-BacFile/bak-sshd_config

sed -i '/^#RSAAuthentication/a\RSAAuthentication no' /etc/ssh/sshd_config

sed -i '/^#PubkeyAuthentication/a\PubkeyAuthentication no' /etc/ssh/sshd_config

if grep ^KerberosAuthentication /etc/ssh/sshd_config
then
        sed 's/^KerberosAuthentication.*/KerberosAuthentication yes/' /etc/ssh/sshd_config;
else
        echo "KerberosAuthentication yes" >> /etc/ssh/sshd_config;
fi

if grep ^KerberosOrLocalPasswd /etc/ssh/sshd_config
then
        sed 's/^KerberosOrLocalPasswd.*/KerberosOrLocalPasswd yes/' /etc/ssh/sshd_config;
else
        echo "KerberosOrLocalPasswd yes" >> /etc/ssh/sshd_config;
fi

if grep ^KerberosTicketCleanup /etc/ssh/sshd_config
then
        sed 's/^KerberosTicketCleanup.*/KerberosTicketCleanup yes/' /etc/ssh/sshd_config;
else
        echo "KerberosTicketCleanup yes" >> /etc/ssh/sshd_config;
fi

cp -rpv /etc/ssh/ssh_config /root/NSI-BacFile/bak-ssh_config

sed -i '/^Host \*/a\        GSSAPIDelegateCredentials yes' /etc/ssh/ssh_config

ntpdate -u ntp1.op.dajie-inc.com

function KADMINPASSWORD
{
        echo -e "Please enter the password of ${RED}Kadmin${DEFAULT}:";
        read -s -p "Password: " KAP;
        if [[ -z ${KAP} ]]
        then
                echo -e "${RED}Please entry the password of kadmin!${DEFAULT}"
                exit;
        fi
}
KADMINPASSWORD;
if [ -e /etc/krb5.keytab ]
then
        echo "File /etc/krb5.keytab already exists!!!"
        exit 0
else
        kadmin -p root/admin -q "addprinc -randkey host/`hostname`@DAJIE-INC.COM " <<< ${KAP};
        kadmin -p root/admin -q "ktadd host/`hostname`@DAJIE-INC.COM" <<< ${KAP};
fi

##############################


##############################
#添加一些别名
##############################

wget 10.10.67.250/nsi/user-profile.sh -O /etc/profile.d/user.sh
#touch /etc/profile.d/user.sh

#echo "alias fgrep='fgrep --color';" >> /etc/profile.d/user.sh
#echo "alias grep='grep --color';" >> /etc/profile.d/user.sh
#echo "alias vi='vim';" >> /etc/profile.d/user.sh
#echo "alias crontab='crontab -i';" >> /etc/profile.d/user.sh
#echo "alias diff='colordiff';" >> /etc/profile.d/user.sh

##############################

##############################
#添加tomcat日志轮转配置
##############################

mkdir -p /ROOT/scripts/tomcat_service_control/
wget http://10.10.67.250/nsi/logrotate_tomcat.conf -O /ROOT/scripts/tomcat_service_control/logrotate_tomcat.conf
/usr/bin/crontab -u root -l > /tmp/crontab.init
echo '59 23 * * * /usr/sbin/logrotate -f -v /ROOT/scripts/tomcat_service_control/logrotate_tomcat.conf' >> /tmp/crontab.init
/usr/bin/crontab -u root /tmp/crontab.init


##############################

##############################
#修改salt客户端
##############################

echo "Backup the salt config file......";
cp -rpv /etc/salt/minion /root/NSI-BacFile/bak-salt-minion

echo 'master: saltmaster.op.dajie-inc.com' > /etc/salt/minion;
echo 'retry_dns: 0' >> /etc/salt/minion;
echo "id: $NEW_IPADDR" >> /etc/salt/minion;

##############################

##############################
#磁盘挂载选项增加noatime
##############################

sed -i 's/defaults/defaults,noatime/' /etc/fstab

##############################

##############################
#zabbix-agentd的相关配置
##############################

ln -s /usr/local/etc/ /etc/zabbix

cp -v /usr/local/etc/zabbix_agentd.conf /root/NSI-BacFile/bak-zabbix_agentd.conf
sed -i 's/^Server=.*/Server=10.10.67.250/' /usr/local/etc/zabbix_agentd.conf
sed -i 's/^ServerActive=.*/ServerActive=10.10.67.250/' /usr/local/etc/zabbix_agentd.conf
sed -i "s/^Hostname=.*/Hostname=$NEW_IPADDR/" /usr/local/etc/zabbix_agentd.conf
echo  "Timeout=30" >> /usr/local/etc/zabbix_agentd.conf

echo "
#Start zabbix-agentd,Add by Dajie-NSI.
/usr/local/sbin/zabbix_agentd &
" >> /etc/rc.local

mkdir -p /ROOT/scripts/Check-listen-ports/

cp -rpv /ROOT/install/nsi/Check-listen-ports /ROOT/scripts/Check-listen-ports/Check-listen-ports
cp -rpv /ROOT/install/nsi/discover-listen-ports.sh /usr/local/etc/discover-listen-ports.sh

chown -R webmaster:webmaster /ROOT/scripts/Check-listen-ports/

echo 'UserParameter=discover.list.listen.port[*],/bin/bash /usr/local/etc/discover-listen-ports.sh' >> /usr/local/etc/zabbix_agentd.conf


##############################

if [[ -e /proc/xen/capabilities ]]
then
        echo "This is a vps!"
else
        yum -y install libsmbios python-smbios smbios-utils-python yum-dellsysid OpenIPMI srvadmin-all
        chkconfig ipmi on
        /bin/bash /opt/dell/srvadmin/sbin/srvadmin-services.sh enable
        chkconfig --list
        /bin/bash /opt/dell/srvadmin/sbin/srvadmin-services.sh start
fi


##############################
#Last message
##############################

#echo "

###################################################################

#       !!!Please change the password of root manually!!!
#               And Reboot the system

###################################################################

#";

#passwd root;


SMTP_SERVER="10.10.67.55"
MAIL_FROM="dwssap@dajie-inc.com"
MAIL_TO="dj-net@dajie-inc.com"
NEW_PASSWD=`mkpasswd -l 16 -C 5 -d 4 -s 0`;
echo ${NEW_PASSWD}
PING_CHECK=`ping -w 2 -c 3 ${SMTP_SERVER} | grep time=`;
echo ${PING_CHECK};
if [[ -z "${PING_CHECK}" ]]
then
        echo "Can not reach SMTP server!!!"
echo "

###################################################################

        !!!Please change the password of root manually!!!
                And Reboot the system

###################################################################

";

passwd root;

else
        /usr/bin/python /ROOT/install/nsi/sendmail.py --host=${SMTP_SERVER} --from=${MAIL_FROM} --to=${MAIL_TO} -c "${NEW_IPADDR} passwd is ${NEW_PASSWD}" -s "dwssap"
        echo "New password has been send to ${MAIL_TO} , please check your email";
#       echo ${NEW_PASSWD} | passwd --stdin root
        echo "root:${NEW_PASSWD}" | chpasswd;
fi


##############################
