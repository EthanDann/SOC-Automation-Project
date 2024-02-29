# Day Three

## Configuring TheHive and Wazuh

- **Configured TheHive:**
    * Edited the `cassandra.yaml` file and changed:
        * Cluster name
        * Listen address to the public IP of the VM created yesterday with DigitalOcean
        * RPC address to the same public IP
        * Seed address to the same IP on port number 7000
    * Restarted the Cassandra service and ensured it was up and running.

- **Configured ElasticSearch:**
    * Changed the ownership of `/opt/thp` to thehive user and thehive group instead of ‘root’.
    * Edited the ElasticSearch yml file and changed:
        * Cluster name to ‘thehive’
        * Un-commented node name
        * Changed network host to the public IP of the VM
        * Un-commented the cluster initial master nodes and removed node 2 because I’m only using node 1.
    * Started and enabled elasticsearch and checked the status to ensure it was running.

- **Configured TheHive application conf:**
    * Edited thehive `application.conf` file to match the cluster name and hostname of thehive configured earlier, as well as the baseUrl to the IP address of thehive.

- **Configured Wazuh:**
    * Accessed Wazuh via the browser and added an agent.
    * Followed the steps provided on the browser, copied and pasted the script provided, and started Wazuh via PowerShell. The Wazuh dashboard showed it as active.

## Reflection

Configuring everything was cool to do, as I got to see what all I can change and it was a nice hands-on experience. It was cool to set my PC up as a Wazuh agent and see it show up on the dashboard; the small wins are always nice.

## Next Steps

Tomorrow I will be generating telemetry from my Windows PC containing Mimikatz, and then trigger a Mimikatz custom alert.
