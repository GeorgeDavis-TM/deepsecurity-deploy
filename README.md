# deepsecurity-deploy
An **idempotent** script to deploy Deep Security agent. An idempotent script can be run multiple times and achieves the exact same result. In this case, activate the Deep Security agent on the machine.

This script runs to execute the following, in the same order
- Checks to see if the script is running as **root**. Installation of the Deep Security agent should be run as root to be successful.
- Checks for the presence of the Deep Security agent locally on the machine. 
    - If found and the status of the agent is GREEN, then displays "All  OK".
    - Else, displays an error message (appears in RED, if the ./agent_health_status_color.sh script was used).
- If the agent is not present or not fully operational i.e. agent status is not GREEN, an installation is attempted to ensure the agent is functional on the machine.

## Prerequisites
- The machine should be Linux-based.
- A valid API key needs to be generated at the Deep Security Manager instance level or on [Trend Micro Cloud One]("https://cloudone.trendmicro.com/management/api-keys").

> The API key needs to be passed to the Bash script as an argument during runtime, like so `sudo ./agent_health_status.sh <your-api-key>`

## Notes
- A security policy wont be assigned. The script only activates the agent with the Deep Security Manager instance that the API key is associated with. A policy can be assigned based on Event-based tasks such as Agent-Initiated Activation, found [here]("https://cloudone.trendmicro.com/docs/workload-security/event-based-tasks/#events-that-you-can-monitor") on the product documentation.
- The API key is used in multiple scenarios as part of this script
    - to fetch the dsmRegion, to build the MANAGERURL variable.
    - to fetch the dsTenantId, to download the agent package from the right DSM.
    - to fetch the dsTenantGUID, for agent activation with the DSM.
    - to fetch the dsDeploymentToken, for agent activation with the DSM.

## Feature requests
- Scripts for Windows, macOS or other platforms were not attempted as part of this project. If you would like to see a similar implementation for the other supported platforms, please feel free to raise an issue on this GitHub repo. Thank you :hearts:

# Credits
@jmlake569 for support in simplifying the script for easier deployments.