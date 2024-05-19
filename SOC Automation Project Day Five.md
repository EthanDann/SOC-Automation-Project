# Day Five

- Connecting Shuffle, Create Workflow
    - Connecting Shuffle
        - Created a workflow
        - Dragged Webhook over and named it ‘Wazuh-Alerts’
        - Clicked on ‘Change Me’ and added a call for an execution argument
        - Edited the ossec.conf file with the integration tag for shuffle and configured it to only send alerts with the rule id of “100002”, the rule id for mimikatz
        - Restarted Wazuh manager
        - Started the Webhook in Shuffle
        - Reran mimikatz in powershell on the Windows 10 VM client
        - Shuffle is now showing the execution argument from Wazuh formatted as JSON
    - Create Workflow in Shuffle
        - Mimikatz alert sent to Shuffle
        - Shuffle receives Mimikatz alert
            - Extract SHA256 hash from file using regex
        - Check reputation score w/ VirusTotal
            - Added VirusTotal to Workflow
            - Set it to get a hash report
            - Set the ‘hash’ parameter to $sha256_regex.group_0.#
            - Send details to TheHive to create alert
            - Added TheHive to Workflow
            - Went to TheHive on browser and created a new organization with two new users; one as the SOC Analyst and the other for Shuffle
            - Created an API key for the Shuffle user
            - Authenticated TheHive in the Workflow
        - Connected TheHive to Workflow
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
        - Reran the workflow and went over to TheHive and the alert was now showing with the details added in the workflow
        - Send email to SOC Analyst to begin investigation
            - Dragged Email to workflow
            - Set a recipient, a subject, and the body to send the time, title, and host computer
            - Reran the workflow and I now received an email to alert me

## Reflection
Setting up this workflow was really cool, I got to see what the capabilities of a SOAR are, although at a small-scale. I could see how sending alerts and emails could contain a lot of useful information for the Analysts to investigate much more efficiently

## Skills Learned
With this being the end of the project, I learned a lot in just five days:
- I created a logical diagram representing the project
- I set up a VM using VirtualBox
- I set up two Ubuntu-based VMs using DigitalOcean and accessed them via SSH
- I navigated files, installed files and services, and edited and configured files in the terminal
- I set up both Wazuh and TheHive and configured them accordingly
- I created a workflow using Shuffle and connected each component to it, boosting incident response time
