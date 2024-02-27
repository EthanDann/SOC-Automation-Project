# ﻿Day One

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
- Creating the logical diagram helped me gain insight into the workflow of a SOC environment, even if it is just one client and one SOC analyst.

## Next Steps

Tomorrow I will be installing each component and getting set up in the cloud
