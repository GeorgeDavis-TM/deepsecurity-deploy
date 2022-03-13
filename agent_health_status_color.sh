#!/bin/bash
dsApiKey=$1

ERR='\033[0;31m'
SUCCESS='\033[0;32m'
WARN='\033[1;33m'
NC='\033[0m' # No Color

CURLOPTIONS='--silent --tlsv1.2';
HEADERS='-H "Authorization: ApiKey ${dsApiKey}" -H "Api-Version: v1" -H "Content-Type: application/json"';
linuxPlatform='';
isRPM='';

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    printf "${ERR}You are not running as the root user.  Please try again with root privileges.${NC}\n";
    logger -t You are not running as the root user.  Please try again with root privileges.
    exit 1;
fi;

hasDSA='';
dsaStatus='';
dsmRegion='';
dsTenantGUID='';

printf "This is a Vanilla bash script to check for ds_agent health associated with Trend Micro Cloud One Workload Security.\n${WARN}Note: This script is not tested for CloudFormation User-data readiness.${NC}\n";
logger -t This is a Vanilla bash script to check for ds_agent health associated with Trend Micro Cloud One Workload Security. Note: This script is not tested for CloudFormation User-data readiness.

echo "Looking for local agent..."
if [[ -f /opt/ds_agent/dsa_query ]]; then
    hasDSA=1    
    dsaStatus=`/opt/ds_agent/dsa_query -c GetAgentStatus | grep AgentStatus.agentState | awk '{print $2}'`
    dsmRegion=`/opt/ds_agent/dsa_query -c GetAgentStatus | grep AgentStatus.dsmUrl | awk '{split($2,url,"."); print url[3]}'`
    dsTenantGUID=`/opt/ds_agent/dsa_query -c GetAgentStatus | grep AgentStatus.dsmDN | awk '{split($2,dn,"/"); print dn[2]}' | awk '{split($1,dn,"="); print dn[2]}'`
fi

# Check for ds_agent status first
if [[ $hasDSA == 1 ]]; then
    if [[ $dsaStatus == "green" ]]; then
        printf "${SUCCESS}All OK${NC}\n";
        logger -t All OK
        exit 0;
    else
        printf "${ERR}Deep Security Agent is not fully operational. Check the Workload Security Manager for more info.${NC}\n";
        logger -t Deep Security Agent is not fully operational. Check the Workload Security Manager for more info.
    fi
fi

# Has ds_agent, but not operational
if [[ $hasDSA == 1 && $dsaStatus != "green" ]]; then

    MANAGERURL="https://workload.${dsmRegion}.cloudone.trendmicro.com:443"
    ACTIVATIONURL='dsm://agents.workload.${dsmRegion}.cloudone.trendmicro.com:443/'

    if ! type curl >/dev/null 2>&1; then
        printf "${ERR}Please install CURL before running this script.${NC}\n";
        logger -t Please install CURL before running this script.
        exit 1;
    fi

    CURLOUT=$(eval curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)

    err=$?
    if [[ $err -eq 60 ]]; then
        printf "${ERR}TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.${NC}\n";
        logger -t TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
        exit 1;
    fi

    if [ -s /tmp/PlatformDetection ]; then
        . /tmp/PlatformDetection
    else
        printf "${ERR}Failed to download the agent installation support script.${NC}\n";
        logger -t Failed to download the Deep Security Agent installation support script.
        exit 1;
    fi

    platform_detect
    if [[ -z "${linuxPlatform}" ]] || [[ -z "${isRPM}" ]]; then
        printf "${ERR}Unsupported platform is detected.${NC}\n";
        logger -t Unsupported platform is detected.
        exit 1;
    fi   

    dsDeploymentToken=$(eval curl -X POST -L $MANAGERURL/api/agentdeploymentscripts -d '{"platform": "linux","validateCertificateRequired": false,"validateDigitalSignatureRequired": false,"activationRequired": true}' $HEADERS $CURLOPTIONS | jq --raw-output '.scriptBody' | tail -n 1 | awk '{split($0,dsToken,"token:"); print dsToken[2]}' | awk '{split($0,dsToken," "); print dsToken[1]}' | awk '{print substr($0,1,length($0)-1)}'  

    # Reset the ds_agent, for good measure
    /opt/ds_agent/dsa_control -r
    # Activate the ds_agent
    /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}"
fi

# Infer no ds_agent installed
if [[ $hasDSA != 1 ]]; then

    if [[ -z "${dsApiKey}" ]]; then
        printf "${ERR}Api Key parameter was not passed when running this script. Retry this script with: sudo ./agent_health_status.sh <your-api-key> <your-deployment=token>.${NC}\n";
        logger -t Api Key parameter was not passed when running this script. Retry this script with: sudo ./agent_health_status.sh <your-api-key> <your-deployment=token>.
        exit 1;
    fi

    apiKeyId=`echo $dsApiKey | awk '{split($1,id,":"); print id[1]}'`    

    if ! type curl >/dev/null 2>&1; then
        printf "${ERR}Please install CURL before running this script.${NC}\n";
        logger -t Please install CURL before running this script.
        exit 1;
    fi

    if ! type jq >/dev/null 2>&1; then
        echo "Please install jq before running this script."
        logger -t Please install jq before running this script.
        exit 1;
    fi

    ACCOUNTURL='https://accounts.cloudone.trendmicro.com/api/apikeys/${apiKeyId}'
    dsmRegion=$(eval curl -L $ACCOUNTURL $CURLOPTIONS $HEADERS | jq '.urn' | awk '{split($1,region,":"); print region[4]}')

    ACTIVATIONURL='dsm://agents.workload.${dsmRegion}.cloudone.trendmicro.com:443/'
    MANAGERURL='https://workload.${dsmRegion}.cloudone.trendmicro.com:443'

    dsTenantId=$(eval curl -L $MANAGERURL/api/apikeys/current $CURLOPTIONS $HEADERS | jq '.tenantID')
    dsTenantGUID=$(eval curl -L $MANAGERURL/api/apikeys/current $CURLOPTIONS $HEADERS | jq --raw-output '.tenantGUID')

    CURLOUT=$(eval curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)
    err=$?
    if [[ $err -eq 60 ]]; then
        printf "${ERR}TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.${NC}\n";
        logger -t TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
        exit 1;
    fi

    if [ -s /tmp/PlatformDetection ]; then
        . /tmp/PlatformDetection
    else
        printf "${ERR}Failed to download the agent installation support script.${NC}\n";
        logger -t Failed to download the Deep Security Agent installation support script.
        exit 1;
    fi

    platform_detect
    if [[ -z "${linuxPlatform}" ]] || [[ -z "${isRPM}" ]]; then
        printf "${ERR}Unsupported platform is detected.${NC}\n";
        logger -t Unsupported platform is detected.
        exit 1;
    fi

    echo "Downloading agent package...."
    if [[ $isRPM == 1 ]]; then package='agent.rpm'
        else package='agent.deb'
    fi
    curl -H "Agent-Version-Control: on" -L $MANAGERURL/software/agent/${runningPlatform}${majorVersion}/${archType}/$package?tenantID=${dsTenantId} -o /tmp/$package $CURLOPTIONS

    echo "Installing agent package...."
    rc=1
    if [[ $isRPM == 1 && -s /tmp/agent.rpm ]]; then
        rpm -ihv /tmp/agent.rpm
        rc=$?
    elif [[ -s /tmp/agent.deb ]]; then
        dpkg -i /tmp/agent.deb
        rc=$?
    else
        printf "${ERR}Failed to download the agent package. Please make sure the package is imported in the Workload Security Manager.${NC}\n";
        logger -t Failed to download the agent package. Please make sure the package is imported in the Workload Security Manager.
        exit 1;
    fi
    
    if [[ ${rc} != 0 ]]; then
        printf "${ERR}Failed to install the agent package.${NC}\n";
        logger -t Failed to install the agent package.
        exit 1;
    fi

    printf "${SUCCESS}Install the agent package successfully.${NC}\n";
    logger -t Install the agent package successfully.

    sleep 15
    /opt/ds_agent/dsa_control -r
    /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}"
    # /opt/ds_agent/dsa_control -a dsm://agents.workload.${dsmRegion}.cloudone.trendmicro.com:443/ "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}"
fi