# Day Two

- Installing all required components
   * Installed Windows 10 Pro on a VM via VirtualBox
      * First installed VirtualBox, comparing the SHA256 hashes to ensure it wasn’t tampered with
      * Then I downloaded the Windows 10 Media Creation Tool to create a ISO file
      * I then ran through the Windows 10 Setup on the VM
   * Installed Sysmon
      * First installed Sysmon, then installed the configuration for it
         * I installed the configuration via PowerShell
   * Installed Wazuh
      * I first created a DigitalOcean account to create a droplet that would host Wazuh
      * I then created a firewall via DigitalOcean to whitelist all TCP and UDP services to only my IP address for inbound traffic
         * I did this to make sure I was the only one that could connect, and no port scanners could pick it up and try to gain access
      * I accessed the VM running Wazuh via SSH
      * Once I logged into the VM via SSH, I installed Wazuh using curl
   * Installed TheHive
      * I installed TheHive using DigitalOcean as well
      * Accessed via SSH as well
      * Once I logged into the VM via ssh, I installed Java, Cassandra, ElasticSearch and then TheHive

### Reflection
  While installing components doesn’t seem like much fun or very interesting, I actually enjoyed it. Installing Wazuh and TheHive via SSH was fun as I’ve never messed with it before. While there was a slight hiccup with TheHive as credentials were not provided by the terminal, the documentation helped resolve it once I found it.

 ## Troubleshooting
   I ran into some trouble with initially logging into TheHive via the browser, as I wasn’t provided with credentials; I resolved this by scouring through the documentation (ironically it was at the very top of the quick start guide) until I found the default admin credentials, which I changed as soon as I logged in

## Next Steps
  Tomorrow I will be configuring TheHive & Wazuh
