# SOC-Automation-Project

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
