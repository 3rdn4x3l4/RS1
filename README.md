# Roger-skyline-1

## SCORE

![FINAL SCORE](https://github.com/3rdn4x3l4/rs1/blob/master/score.png)

## VM

### VM creation

First I use `vm_manager` script like so:
```
./vm_manager
```

The scripts asks for the name, the path, the ISO path, the RAM, the number of CPU cores, and the disk size to use.
Now the VM exists, it is ready to be installed

you can launch the VM with the graphical interface of VirtualBox or use the following command:
```
VBoxManage startvm "VM_NAME"
```

quotes for the name are not mandatory of course

### VM installation

For this part I choose to use the automated install of my ISO. However I need to enter manually the information (ex: root password, username, user password, partition sizes and mountpoints...)

## SSH

### SSH settings on the Host

From the host we only need to send the keys to the guest to be able to connect form Host to Guest.
SSH keys can be sent using the ssh-copy-id command:
```
ssh-copy-id -i ~/.ssh/id_rsa.pub user@host_IP 
#here -i options gives the path to the publickey to be sent
```

If you have encrypted your key it will ask for the passphrase.

### SSH settings on the Guest

On the host we don't want root to be able to connect, we don't want to use the default ssh port (22), and we want to use publickey to authentificate into the machine.

For this three tasks we edit the `/etc/ssh/sshd_config` file:

The following lines will be modified
```
#Port 22
#PermitRootLogin prohibit-password
#PasswordAuthentification yes
```

into
```
Port 4242	#I choose to use the 4242 port for my ssh connection
PermitRootLogin no	#I prevent root to connect via ssh
PasswordAuthentification no	#Password authentification is too weak and password are sent unencrypted
```

## Install softwares

I execute the script named install (basically a apt install ...) this install the binaries necesary to the roger project.

## Sudo, static IP and crontabs

### Sudo

When SSH is set up we still need to give the user rights to run command that needs root privileges.
The install script installed sudo among the rest: root can now edit the sudoers file to add the user
```
vim /etc/sudoers
```

We add
```
user ALL=(ALL:ALL) ALL
```

right under
```
root ALL=(ALL:ALL) ALL
```

### static IP

To get a static IP we need to change the default settings of the network interface which uses DHCP when installing the VM, the file is `/etc/network/interfaces`:
```
# The primary network interface
allow-hotplug enp0s3
iface enp0s3 inet dhcp
```

become
```
# The primary network interface
auto enp0s3
iface enp0s3 inet static
	address 10.12.213.213/30
	gateway 10.12.254.254
```

### Crontabs

Crontabs let us create fixed time tasks.
Here we want to launch a script that will update our system and log everything in `/var/log/update_script.log` everytime we reboot and every week, one day of the week at 4h00 AM.
And we also want to check if `/etc/crontab` has been modified.

we can edit the crontab by using the command:
```
sudo crontab -e
```

we add the follwing lines to file:
```
0 4 * * 0 /home/defuser/scripts/update
@reboot /home/defuser/scripts/update
0 0 * * * /home/defuser/script/check_cron
```

## Web server

### Apache settings and SSL certification

I choose to change the default path of the web server by modifying the `/etc/apache2/apache2.conf`
default is :
```
<Directory /var/www/>
		Options Indexes FollowSymLinks
		AllowOverride None
		Require all granted
</Directory>
```

after modification it is:
```
<Directory /home/defuser/serverweb/>
		Options Indexes FollowSymLinks
		AllowOverride None
		Require all granted
</Directory>
```

To create a SSL certificate I use the command:

```
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt
```
This command ask us a few information to fill the certificate.

Of course the certificate and the key can be named as we want and place wherever we would like to.

Next step is to tell our apache server how to use the certificate, we need to create a configuration file for SSL.
```
sudo vim /etc/apache2/conf-available/my-ssl.conf
```

we add these few lines into the file
```
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
```

we then modify the `/etc/apache2/sites-available/default-ssl.conf` file
```
ServerAdmin webmaster@localhost
DocumentRoot /var/www/html
...

SSLCertificateFile      /etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
```

become
```
ServerAdmin webmaster@localhost
ServerName 10.12.213.213
DocumentRoot /home/defuser/serverweb

...

SSLCertificateFile      /etc/ssl/certs/apache-selfsigned.crt
SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
```
I add HTTP to HTTPS redirection to be a bit more secure by editing `/etc/apache2/sites-available/000-default.conf` file:
```
Redirect "/" "https://10.12.213.213"
```
we also change the ServerAdmin to be our email address and the Document root to be where our serverweb files are located:
```
ServerAdmin root@localhost
DocumentRoot /var/www/html
```

become
```
ServerAdmin email@example.com
DocumentRoot /home/defuser/serverweb
```

then we tell apache to enable modules, to change virtual host, and enable ssl config with:
```
sudo a2enmod ssl
sudo a2enmod headers
sudo a2ensite default-ssl
sudo a2enconf ssl-params
```

to make sure there is no error we use:
```
sudo apache2ctl configtest
```

Only then we can reload apache service with the new changes
```
sudo systemctl restart apache2
```
### Deployment

To deploy the web server automatically I use git hooks:
in the home directory of my user
```
mkdir webhooks.git
cd webhooks.git
git init --bare
cd hooks
touch post-receive
chmod +x post-receive
```

then we add into the script
```
#!/bin/bash
while read oldrev newrev ref
do
	if [[ $ref =~ .*/master$ ]];
	then
		echo "Master ref received.  Deploying master branch to production..."
		git --work-tree=/home/defuser/serverweb --git-dir=/home/defuser/webhooks.git checkout -f
	else
		echo "Ref $ref successfully received.  Doing nothing: only the master branch may be deployed on this server."
	fi
done
```
On the server side everything is ready, now from a remote location where our website files are located:
```
git init
```
and we add a remote link to this git with:
```
git remote add $linkname ssh://username@VM_IP:SSH_PORT/home/defuser/webhooks.git
```
Now we can push to the remote using:
```
git push $linkname master
```

## Firewall, DOS and Portscans protection 

### Firewall

I use ufw to create the firewall:
```
sudo ufw limit 4242 #to allow SSH connection
sudo ufw allow 80
sudo ufw allow 443 #these ports are the one used by http/s
```

### DOS prevention

I use fail2ban to prevent people to DOS me, to do so i edit the `/etc/fail2ban/jail.local` file:
```
[sshd]
port = 4242
enabled = true
maxretry = 3
findtime = 60
bantime = 120
mode = extra

[recidive]
enabled = true

[apache]
enabled = true
port = http, https
filter = apache-auth
logpath = /var/log/apache2*/*error.log
maxretry = 6
findtime = 600

[apache-noscript]
enabled = true

[apache-overflows]

enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache2*/*error.log
maxretry = 2

[apache-badbots]

enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2*/*error.log
maxretry = 2

[http-get-dos]
enabled = true
port = http,https
filter = http-get-dos
logpath = /var/log/apache2/*.log
maxretry = 100
findtime = 300
bantime = 300
action = iptables[name=HTTP, port=http, protocol=tcp]
```

in the `/etc/fail2ban/filter.d/http-get-dos.conf` file:
```
[Definition]

# Option: failregex
# Note: This regex will match any GET entry in your logs, so basically all valid and not valid entries are a match.
# You should set up in the jail.conf file, the maxretry and findtime carefully in order to avoid false positives.

failregex = ^<HOST> -.*"(GET|POST).*

# Option: ignoreregex
# Notes.: regex to ignore. If this regex matches, the line is ignored.
# Values: TEXT
#
ignoreregex =
```

### Portscan protection

I use portsentry to prevent people to scan my VM:

I edit the `/etc/defaults/portsentry` file
```
TCP_MODE="tcp"
UDP_MODE="udp"
```

become
```
TCP_MODE="atcp"
UDP_MODE="audp"
```

and the `/etc/portsentry/portsentry.conf` file
```
...
# Un-comment these if you are really anal:
#TCP_PORTS="1,7,9,11,15,70,79,80,109,110,111,119,138,139,143,512,513,514,515,540,635,1080,1524,2000,2001,4000,4001,5742,6000,6001,6667,12345,12346,20034,27665,30303,32771,32772,32773,32774,31337,40421,40425,49724,54320"
#UDP_PORTS="1,7,9,66,67,68,69,111,137,138,161,162,474,513,517,518,635,640,641,666,700,2049,31335,27444,34555,32770,32771,32772,32773,32774,31337,54321"
#
# Use these if you just want to be aware:
TCP_PORTS="1,11,15,79,111,119,143,540,635,1080,1524,2000,5742,6667,12345,12346,20034,27665,31337,32771,32772,32773,32774,40421,49724,54320"
UDP_PORTS="1,7,9,69,161,162,513,635,640,641,700,37444,34555,31335,32770,32771,32772,32773,32774,31337,54321"
...
BLOCK_UDP="0"
BLOCK_TCP="0"
...
#KILL_ROUTE="/sbin/iptables -INPUT -s $TARGET$ -j DROP"
...
KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
```

become
```
...
# Un-comment these if you are really anal:
TCP_PORTS="1,7,9,11,15,70,79,80,109,110,111,119,138,139,143,512,513,514,515,540,635,1080,1524,2000,2001,4000,4001,5742,6000,6001,6667,12345,12346,20034,27665,30303,32771,32772,32773,32774,31337,40421,40425,49724,54320"
UDP_PORTS="1,7,9,66,67,68,69,111,137,138,161,162,474,513,517,518,635,640,641,666,700,2049,31335,27444,34555,32770,32771,32772,32773,32774,31337,54321"
#
# Use these if you just want to be aware:
#TCP_PORTS="1,11,15,79,111,119,143,540,635,1080,1524,2000,5742,6667,12345,12346,20034,27665,31337,32771,32772,32773,32774,40421,49724,54320"
#UDP_PORTS="1,7,9,69,161,162,513,635,640,641,700,37444,34555,31335,32770,32771,32772,32773,32774,31337,54321"
...
BLOCK_UDP="1"
BLOCK_TCP="1"
...
KILL_ROUTE="/sbin/iptables -INPUT -s $TARGET$ -j DROP"
...
#KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
```
