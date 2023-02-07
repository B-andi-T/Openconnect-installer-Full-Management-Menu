<p align="center">
  <img width="400" height="300" src="https://user-images.githubusercontent.com/118496203/203834573-5180b92c-eccf-4d29-a866-244f607f079f.png">
</p>

# Secured OCSERV+LetsEncrypt+Menu (Ubuntu 18.04 , 20.04 , 22.04)
A script that allows you to install and configure OpenConnect and LetsEncrypt on your Ubuntu server in the simplest way.

#### Compatibility

*   Ubuntu 18.04 - 20.04 - 22.04

#### Requirement
* A domain is required to obtain the Certificate (If you want to buy a cheap domain, you can buy one from NameCheap. Namecheap also supports cryptocurrency payment method + free whois privacy protection
* Server Root Access
* *Important : LetsEncrypt needs port 80 to obtain the certificate. The script automatically detects Apache and Nginx if they are installed and will perform the installation based on that. If you have another process on port 80 besides Apache and Nginx, stop it before starting the installation so that port 80 is open during the process. After installation, you can reactivate your stopped service.

## Why use this script?
### **First, let's see the initial steps of installation** 
#### You need to answer a few simple questions, Then you won't have to do anything except wait a few moments and script will do :
* First, it installs OCSERV & LetsEncrypt automatically
* Then it obtains a certificate with the Stand-Alone plugin or with the Webroot plugin for Apache or Nginx automaticlly.
* Then it configures the OCSERV automatically
* Then it configures the Firewall automatically
* Then... that's it!

### After finishing the installation and configuration, now you have access to a Menu by running the script again.
## Features that you'll have access in the menu
* #### Users Menu :
In the Users Menu, you can add a new user, delete an existing user, change username or password for each user, see the list of all users, see connected users, disconnect a connected user, add a separate configuration for each user.
* #### OCSERV Menu :
In the OCSERV Menu, you can check the current status of each OCSERV services that you have created, restart or stop each OCSERV services that you have. view OCSERV log and change the current port.
* #### LetsEncrypt Menu :
In the LetsEncrypt Menu, You can add a new certificate, delete a certificate, change the certificate for your desired OCServ(s), Renew your certificates and see the current certificates that you already have.
* #### Add Multiple OCServ :
In the Add Multiple OCServ Menu, You can add multiple OCSERVs! Each of them can have a new domain and a new port. A separate service and configuration will be created for each one. Then, you can use OCSERV Menu to view the status or restart, remove, reconfig each one.

### You will also have an option to completely remove OCSERV(s) from the server.
## How to use
Download and execute the script
```
wget https://raw.githubusercontent.com/B-andi-T/Openconnect-installer-Full-Management-Menu/main/Ocserv-Installer.sh
chmod +x Ocserv-Installer.sh
./Ocserv-Installer.sh
```
Now answer a few simple questions and wait for the installation and configuration to finish.

that's it!


Now, if you run the script again, you will be redirected to the menu.
At the top of the menu, you can see server specifications, OCServ version and service status. The menu contains most of the options you will need to manage your OCServ.

### Futex facility returned an unexpected error (ubuntu 22.04)
Please note, if you are using Ubuntu 22.04 and you are unable to connect the client to the server after completing the installation, check the server status and if you see The ""futex facility returned an unexpected error"", select the FIX OCServ Futex Error (Ubuntu 22.04) option from the OCServ menu and Wait for the operation to complete. Then connect the client again

## Do you live in a country where ocserv is blocked?
Since ocserv is blocked in some countries (such as Iran), if you live in these countries and want to use ocserv, you can ssh tunnel to your main server through a local server.

for example :

You have a local server (a VPS inside your country) called server A and your destination server where ocserv is installed is called server B.
First, make sure OCServ is active on server B without errors.

Run the following command on server A:
```
ssh -p {SERVER B SSH PORT} -f -N -L 0.0.0.0:{ANY PORT YOU WANT}:{SERVER B IP}:{SERVER B OCSERV PORT} root@{SERVER B IP}
```
example : 
```
ssh -p 22 -f -N -L 0.0.0.0:2222:2.2.2.2:2222 root@2.2.2.2
```
-If the firewall is active on your server, you should open the port you are using.

Now connect the client to your local server (such as mobile, computer, etc.). as below:
```
yourlocalserverIP:PORT
```
of course you will see the ""untrusted server"" message popup when connecting, and the reason is that you are not connecting directly to the main server where your domain and certificate are located.

## Clients
- [x] OpenConnect for Windows: https://github.com/openconnect/openconnect-gui/releases/download/v1.5.3/openconnect-gui-1.5.3-win32.exe
- [x] Anyconnect for Android: https://play.google.com/store/apps/details?id=com.cisco.anyconnect.vpn.android.avf&hl=en&gl=US
- [x] Anyconnect for IOS devices: https://apps.apple.com/us/app/cisco-secure-client/id1135064690


## Donation
If you are happy with my script, you can make me happy too with a small amount of donation!

- [x] My Tether(USDT) TRC20 Wallet : TS3ipuQo27mXqxzrehtupgHrMyjKmf7wKz
- [x] My Dash Wallet : XokprTdUa9B2fXmSZF6ErdrVQWg6MTtebj
- [x] My BitcoinCash Wallet : qz8uz6k7rwymtlad2rlhlqhxntl6t39s8g96kcumac
- [x] My LiteCoin Wallet : ltc1qkw00pa4u4wmhnl807v4grca0qpq2pl0z26hc8k

Cheers!
