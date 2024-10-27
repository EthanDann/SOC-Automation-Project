# SOC Automation Project

The goal of this project was to gain hands-on experience with a SOC Analyst’s tools, including writing better documentation! The project took me from design to start (from scratch) and then to a fully functional lab with responsive capabilities and case management.

## Components Used

- **Wazuh**: Wazuh is used as the SIEM (Security Information and Event Management) and XDR (Extended Detection and Response) platform. It provides real-time monitoring, threat detection, and response capabilities for security incidents.

- **TheHive**: TheHive is used for case management. It is a centralized platform for incident response, allowing the creation, management, and tracking of alerts and investigations efficiently.

- **Shuffle**: Shuffle is used for SOAR (Security Orchestration, Automation, and Response) capabilities. It allows the automation of repetitive tasks, orchestration of security workflows, and integration with different security tools and systems.

## Project Logical Diagram

![SOC Automation Project Diagram](SOC%20Automation%20Project%20Diagram.jpg)

- Create Logical Diagram:
  * Windows 10 Client (Wazuh Agent)
      * Sends events to the Wazuh Manager
      * Acts as a primary source of endpoint data
   * Wazuh Manager
      * Receives events from Windows 10 Client
      * Sends alerts to Shuffle
   * Shuffle
      * Receives Wazuh alerts from Wazuh Manager
      * Sends alerts to TheHive for case management
      * Sends email notifications to SOC analyst
   * SOC Analyst:
      * Receives email notifications from Shuffle
      * Takes responsive actions based on the alert
      * Communicates responsive actions back to Shuffle and Wazuh Manager
   * OSINT Enrichment
      * Enriches IOCs with OSINT data
      * Enhances the context and understanding of potential threats
   * TheHive (Case Management)
      * Creates and manages alerts within the case management system
      * Provides a centralized platform for incident response and collaboration
   * Email
      * Sends email notifications for critical alerts or incidents
   * Router
      * Ensures connectivity amongst all devices within the network and provides access to the internet
      * Forwards network packets between devices within the local network and beyond
   * Internet
      * Enables connectivity to resources and services beyond the local network
- Installing all required components
   * Install Windows 10 Pro on a VM via VirtualBox
      * First install VirtualBox, comparing the SHA256 hashes to ensure it wasn’t tampered with
      * Download the Windows 10 Media Creation Tool to create a ISO file
      * Run through the Windows 10 Setup on the VM
   * Installed Sysmon
      * Install Sysmon, then install the configuration for it on Github
         * Install the configuration via PowerShell
   * Install Wazuh
      * Create a DigitalOcean account to create a droplet that will host Wazuh
      * Create a firewall via DigitalOcean to whitelist all TCP and UDP services to only my IP address for inbound traffic
         * Do this to make sure you are the only one that can connect, and no port scanners can pick it up and try to gain access
      * Access the VM running Wazuh via SSH
      * Once logged in, install Wazuh using curl
        ```bash
         curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
        ```
      * Extract Wazuh Credentials
       ```bash
        sudo tar -xvf wazuh-install-files.tar
       ```
   * Install and configure TheHive
      * Once again, create another Ubuntu VM with the same firewall configuration
      * Access the machine via SSH
      * Once logged in, install Java, Cassandra, ElasticSearch and then TheHive
        * First install dependencies
           ```bash
            apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
           ```
        * Install Java
            ```bash
             wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
             echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
             sudo apt update
             sudo apt install java-common java-11-amazon-corretto-jdk
             echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
             export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
            ```
        * Install Cassandra
            ```bash
             wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
             echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
             sudo apt update
             sudo apt install cassandra
            ```
        * Install ElasticSearch
            ```bash
             wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
             sudo apt-get install apt-transport-https
             echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
             sudo apt update
             sudo apt install elasticsearch
            ```
          * ***OPTIONAL ELASTICSEARCH***
            * Do this if you're getting errors when trying to log in using the default credentials
            * Create a jvm.options file under /etc/elasticsearch/jvm.options.d and paste the following configurations in that file, this tells it to allocate 2gb of memory for Java rather than 4gb
              * Dlog4j2.formatMsgNoLookups=true
              * Xms2g
              * Xmx2g
            * Once created, restart ElasticSearch service
         * Install TheHive
            ```bash
             wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
             echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
             sudo apt-get update
             sudo apt-get install -y thehive
            ```
         * Default Credentials on port 9000
           * credentials are 'admin@thehive.local' with a password of 'secret'
