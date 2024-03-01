# Day Four

- Generating Telemetry & Ingesting into Wazuh
    - Generate Telemetry
        - Configured `ossec.conf` file.
            - Created backup of `ossec.conf` file as precaution.
            - Added ‘symon’ as a local file for log analysis in `ossec.conf`.
            - Restarted Wazuh service.
        - Excluded downloads folder from being scanned, to prepare for mimikatz download.
        - Downloaded mimikatz to downloads folder.
        - Ran mimikatz in PowerShell.
        - Went to Wazuh security events and searched for ‘mimikatz’, nothing showed of course because an alert has not been created for it yet.

- Ingest into Wazuh
    - Accessed Wazuh manager via SSH and created a copy of `ossec.conf` file as a precaution before editing.
    - Edited the `ossec.conf` file to log all and log all json.
    - Restarted `wazuh-manager` service.
    - Edited `filebeat.yml` and set archives as enabled so Wazuh can start to ingest these files, then restarted `filebeat`.
    - Then went back to Wazuh browser, created a new index pattern for the archives.
    - Searched for ‘mimikatz’ once again, but nothing was showing still because mimikatz was not ran after I edited the file to log everything.
    - Ran mimikatz once again from PowerShell and ‘mimikatz’ was now showing up.
- Created a custom rule in Wazuh for mimikatz.
    - Set rule id to ‘100002’ and level ‘15’ (for demo purposes).
    - Set the field name to look for the originalFileName of ‘mimikatz\.exe’.
    - Set the description to ‘Mimikatz Usage Detected’.
    - Finally set the mitre id to ‘T1003’ for credential dumping, since mimikatz is known to do that.
    - Restarted the manager.
    - Changed the mimikatz.exe file’s name to ‘youareawesome’ to check that the `originalFileName` field was working correctly.
- Mimikatz was now showing up in the security events archives log.

## Reflection
This was really cool to do, even though it’s just a demo environment and small-scale, it gave me practical experience in creating custom rules, setting up alerts, etc.

## Next Steps
Tomorrow I will be connecting Shuffle for SOAR capabilities, sending alerts to TheHive, and sending alerts to “SOC Analyst” via Email.
