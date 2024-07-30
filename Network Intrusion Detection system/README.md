# CodeAlpha_Network_Intrusion_Detection_system
### Overview
This repository contains a step by step guide for setting up a network intrusion detection system using SNORT developed during my Task 3 of my cybersecuirty CodeAlpha internship  .
### Requirements 
- Set up a network  where all your vms can communicate
- For setting snort ( use a vm linux distrution or ubuntu prefered )
- Privileged/Administrative Rights
- Download the metasploitable 2 linux server : https://sourceforge.net/projects/metasploitable/

### Usage
1. Set and configure snort 
  - For ubuntu : https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux
  - For Kali : https://bin3xish477.medium.com/installing-snort-on-kali-linux-9c96f3ab2910
  - Make sure to do back up for snort.conf
2. Write ur local rules or use snort default rules ( you will in this repository my written local rules )
    ``` vim /etc/snort/rules/local.rules  ```
3. Start snort
   ``` sudo snort -q -l /var/log/snort -i eth0 ( check ur interface name ) -A console -c snort.conf  ```
4. Do namp scan on Metasploitable 2 , use Metasploit framework to perform ur attacks and see the alerts coming.
Ps : If any error appear keep checking and fix it .

### Ressources
+ https://www.youtube.com/watch?v=Gh0sweT-G30
+ https://www.youtube.com/watch?v=r1Z7SxewjhM
