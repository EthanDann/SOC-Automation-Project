# SOC Automation Project

The goal of this project is to gain hands-on experience with a SOC Analyst’s tools. The project will take you from design to start (from scratch) and then to a fully functional lab with responsive capabilities and case management.

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
   * Install TheHive
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
         * Install TheHive
            ```bash
             wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
             echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
             sudo apt-get update
             sudo apt-get install -y thehive
            ```
         * Default Credentials on port 9000
           * credentials are 'admin@thehive.local' with a password of 'secret'
- Configuring TheHive and Wazuh
   - **TheHive Configuration:**
       * Edited the `etc/cassandra/cassandra.yaml` file and changed:
           * cluster_name
           * listen_address to the public IP of the VM
           * rpc_address to the same public IP
           * seeds under seed_provider to the same IP on port number 7000
       * Restarted the Cassandra service and ensured it was up and running.
             ```bash
             systemctl stop cassandra.service
             ## remove old files because we used TheHive package
             rm -rf /var/lib/cassandra/*
             systemctl start cassandra.service
             systemctl status cassandra.service
             ```
   - **ElasticSearch Configuration:**
       * Edited the `etc/elasticsearch/elasticsearch.yml` file and changed:
           * cluster.name to ‘thehive’
           * Un-commented node.name
           * Changed network.host to the public IP of the VM
           * Un-commented http.port
           * Un-commented the cluster.initial_master_nodes and removed node 2 because only node 1 will be used.
       * Started and enabled elasticsearch and checked the status to ensure it was running.
       * Changed the ownership of `/opt/thp` to thehive user and thehive group instead of ‘root’.
            ```bash
            chown -R thehive:thehive /opt/thp
            ```
       * ***Optional Configuration***
            * Do this if you're getting errors when trying to log in using the default credentials
            * Create a jvm.options file under /etc/elasticsearch/jvm.options.d and paste the following configurations in that file, this tells it to allocate 2gb of memory for Java rather than 4gb
              * Dlog4j2.formatMsgNoLookups=true
              * Xms2g
              * Xmx2g
            * Once created, restart ElasticSearch service
   - **Configuring TheHive application.conf:**
       * Edited thehive `etc/thehive/application.conf` file to match the cluster-name and hostname of thehive configured earlier, as well as the application.baseUrl to the IP address of thehive.
       * Start TheHive service
         ```bash
         systemctl start thehive
         systemctl enable thehive
         systemctl status thehive
         ```
   - **Adding Wazuh Agent:**
       * Access Wazuh via the browser and add an agent.
          * Follow the steps provided on the browser, copy and past the script provided, and start Wazuh via PowerShell. The Wazuh dashboard will show it as active.
              ```bash
              net start wazuhsvc
              ``` 
              * If the agent doesn't show up right away, just give it a minute and it should.
- Generating Telemetry & Ingesting into Wazuh
    - Generate Telemetry
        - Configure `ossec.conf` file.
            - Create backup of `ossec.conf` file as precaution.
            - Add ‘symon’ as a local file for log analysis in `ossec.conf`.
                - Under the 'Log analysis' section, add in the following:
                  `<localfile>
                      <location>Microsoft-Windows-Sysmon/Operational</location>
                      <log_format>eventchannel</log_format>
                   </localfile>`
                - For sake of ingestion, remove the 'Application' and 'Security' and 'System' localfiles to only capture Sysmon events
                    - Can keep these in, this project is only capturing sysmon events so the others aren't necessary
            - Restart Wazuh service.
        - Go to Wazuh dashboard to see if sysmon events are being captured
            - May need to wait a few minutes
        - Exclude downloads folder from being scanned, to prepare for mimikatz download.
            - Under 'Virus & Threat Protection', add an exclusion to your downloads folder
        - Download mimikatz to downloads folder via Github.
            - May need to disable protection on your browser settings
        - Run mimikatz in PowerShell with admin privileges.
            ```bash
            cd C:\Users\{user}\Downloads\mimikatz_trunk\x64
            .\mimikatz.exe
            ``` 
        - Go to Wazuh security events and search for ‘mimikatz’, nothing should show because an alert has not been created for it yet.
- Ingest into Wazuh
    - Access Wazuh manager via SSH and create a copy of `ossec.conf` file as a precaution before editing.
        ```bash
        cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
        ``` 
    - Edit the `ossec.conf` file and set 'logall' to 'yes' and 'log_all_json' to 'yes'.
    - Restart `wazuh-manager` service.
        ```bash
        systemctl restart wazuh-manager.service
        ```
    - Logs will be placed in `/var/ossec/logs/archives`
    - Edit `etc/filebeat/filebeat.yml` and set 'archives' to 'true' so Wazuh can start to ingest these files, then restart filebeat.
    - Go back to Wazuh dashboard, and create a new index pattern for the archives.
        - Under 'Management', then 'Stack Management'
        - Click 'create index', and name the index 'wazuh-archives-*'
        - Set time field to 'timestamp'
        - Then click 'create index pattern'
    - Set the index to the 'wazuh-archives-*' index you just created
    - Search for ‘mimikatz’ once again, and nothing should show up because mimikatz was not ran after the file was edited to log everything.
    - Run mimikatz once again from PowerShell and ‘mimikatz’ should now show up.
    - Create a custom rule in Wazuh for mimikatz.
        - Click home button o Wazuh dashboard, then 'Management' then 'Rules', then click 'Manage rule files'
        - Copy one of the rules from one of the sysmon rules already created from `0800-sysmon_id_1.xml`
        - Click 'custom rules' and edit the `local_rules.xml` file, and follow the same format when adding the following:
            - Set rule id to ‘100002’ and level ‘15’ (for demo purposes).
            - Set the field name to look for the originalFileName of `(?i)mimikatz\.exe`.
            - Set the description to ‘Mimikatz Usage Detected’.
            - Finally set the mitre id to ‘T1003’ for credential dumping, since mimikatz is known to do that.
        - Restart the manager when prompted.
        - Change the mimikatz.exe file’s name to ‘youareawesome’ to check that the `originalFileName` field is working correctly.
        - Start mimikatz using the new name
            ```bash
            .\youareawesome.exe
            ``` 
    - Mimikatz should now show up on the dashboard
- Connect Shuffle and Creating Workflow
    - Connect Shuffle
        - Create a workflow
            - Drag Webhook over, click on it and name it ‘Wazuh-Alerts’
                - Copy the Webhook URI for later use
            - Click on ‘Change Me’, make sure it's set to 'Repeat back to me' and add a call for an execution argument (add `$exec` under the 'Call' section)
            - Edit the ossec.conf file with the integration tag for shuffle and configure it to only send alerts with the rule id of “100002”, the rule id for mimikatz
                - Add the following under the <global> tag, following the same format used in the other tags:
                ```bash
                <integration>
                  <name>shuffle</name>
                  <hook_url>{hook_uri}</hook_url>
                  <rule_id>100002</rule_id>
                  <alert_format>json</alert_format>
                </integration>
                ```
                - Instead of 'hook_uri', paste in the uri copied earlier
            - Restart Wazuh manager
                ```bash
                systemctl restart wazuh-manager.service
                systemctl status wazuh-manager.service
                ``` 
            - Start the Webhook in Shuffle
            - Rerun mimikatz (.\youareawesome.exe) in powershell
            - Shuffle should now show the execution argument from Wazuh formatted as JSON if you click on Workflow runs (the running icon)
    - Create Workflow in Shuffle
        - Mimikatz alert sent to Shuffle
        - Shuffle receives Mimikatz alert
            - Extract SHA256 hash from file using regex
                - Click on the Change Me icon
                    - Set the 'find actions' to 'Regex capture group'
                    - Under 'input data' select the `+` sign and then Execution argument
                        - Set it to 'hashes'
                    - Under 'Regex' set it to `SHA256=([09-A-Fa-f]{64}])`
                        - If having trouble, just search for how to write regex for the SHA256 hash
            - Rerun the workflow
        - Check reputation score w/ VirusTotal
            - Add VirusTotal to Workflow
                - Create an account on VirusTotal (free), and copy the API key
            - Set it to get a hash report
            - Set the ‘hash’ parameter to $sha256_regex.group_0.#
            - Send details to TheHive to create alert
            - Add TheHive to Workflow
            - Go to TheHive on browser and create a new organization with two new users; one as the SOC Analyst and the other for Shuffle
            - Create an API key for the Shuffle user
            - Authenticate TheHive in the Workflow
        - Connect TheHive to Workflow
            - Set TheHive to create an alert that contains details of the incident
            - Specific details:
                - utcTime
                - description as ‘Mimikatz detected on host: “...system.computer” from user: “...eventdata.user”’
                - pap as 2
                - severity as 2
                - source as ‘Wazuh’
                - sourceRef as ‘Rule: 100002’
                - summary as ‘host: “...system.computer” and the process ID: “...eventdata.processID, and the command line is: “...eventdata.commandLine”, the tag as “T1003”
                - the title as “$exec.title”
                - tlp as 2
                - type as Internal
        - Rerun the workflow and go to TheHive and the alert should now show with the details added in the workflow
        - Send email to SOC Analyst to begin investigation
            - Drag Email to workflow
            - Set a recipient, a subject, and the body to send the time, title, and host computer
            - Rerun the workflow and you should now receive an email to alert you 
