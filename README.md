
# ThinkingSOC Alert Action for Splunk

## Overview
**ThinkingSOC Alert Action for Splunk** is a custom alert action designed for seamless integration between Splunk and Thinking SOC. It sends all the necessary data for analysis from Splunk directly to Thinking SOC, enabling efficient data processing and insight generation.

## Configuration Fields

### URL
- **Description:**  
  The full URL of the Thinking SOC API endpoint that will receive the alert data.
- **Example:**  
  `http://example.com/webhook`

### Username & Password
- **Description:**  
  Optional credentials for authenticating the webhook request.  
  If left blank, the alert data is sent without authentication.
- **Example:**  
  - **Username:** `admin`  
  - **Password:** `secret`

### Description
- **Description:**  
  A brief description of the alert or event, providing context for the data sent to Thinking SOC.
- **Example:**  
  `"Suspicious login attempt from an unknown IP."`

### Severity
- **Description:**  
  Indicates the urgency or criticality of the alert, helping to prioritize events.
- **Options:**  
  - (None)
  - Info
  - Low
  - Medium
  - High
  - Critical
- **Example:**  
  `"Critical"`

### MITRE Tactics
- **Description:**  
  (Optional) One or more MITRE ATT&CK tactics associated with the alert.  
  Enter multiple tactics separated by a comma (`,`).
- **Example:**  
  `"Initial Access, Execution"`

### MITRE Techniques
- **Description:**  
  (Optional) One or more MITRE ATT&CK techniques related to the alert.  
  Enter multiple techniques separated by a comma (`,`).
- **Example:**  
  `"Spearphishing Attachment, Credential Dumping"`

## Purpose
This integration sends the essential data required for analysis from Splunk to Thinking SOC. It is designed to bridge Splunk's alerting capabilities with Thinking SOC’s analytical tools, ensuring that alerts information is reliably forwarded for further analysis.
