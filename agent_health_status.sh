#!/usr/bin/env bash
verbose=false

usage() { echo "Usage: $0 --api-key | -a <valid-api-key> [--policyid | -p <policy-id>] [--verbose | -v] [--help | -h]" 1>&2; exit 1; }

obfuprintperc () {
    local perc=50  ## percent to obfuscate
    local i=0
    for((i=0; i < ${#1}; i++))
    do
    if [ $(( $RANDOM % 100 )) -lt "$perc" ]
    then
        printf '%s' '*'
    else
        printf '%s' "${1:i:1}"
    fi
    done
    echo
}

# make args an array, not a string
args=( )

# replace long arguments
for arg; do
    case "$arg" in        
        --apikey)         args+=( -a ) ;;
        --policyid)       args+=( -p ) ;;
        --verbose)        args+=( -v ) ;;
        --help)           args+=( -h ) ;;
        *)                args+=( "$arg" ) ;;
    esac
done

set -- "${args[@]}"

while getopts "a:p::vh" opt; do
    case "${opt}" in
        a)
            dsApiKey=${OPTARG}            
            ;;
        p)
            dsPolicyId=${OPTARG}            
            ;;
        v)
            verbose=true
            echo NOTE: verbose is set to $verbose
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "${dsApiKey}" ]; then
    usage
fi

${verbose} && printf "API Key: " && obfuprintperc ${dsApiKey}
${verbose} && echo "Policy Id: ${dsPolicyId}"

if [[ -z "${dsPolicyId}" ]]; then    
    dsPolicyId=1
    echo "Bash argument dsPolicyId is empty. Activating DS Agent with Base Policy (dsPolicyId = ${dsPolicyId})";
    logger -t Bash argument dsPolicyId is empty. Activating DS Agent with Base Policy \(dsPolicyId = $dsPolicyId\)
fi

${verbose} && echo "DS Policy Id - ${dsPolicyId}";
${verbose} && logger -t DS Policy Id - $dsPolicyId

CURLOPTIONS='--silent --tlsv1.2';
HEADERS='-H "Authorization: ApiKey '${dsApiKey}'" -H "Api-Version: v1" -H "Content-Type: application/json"';
linuxPlatform='';
isRPM='';

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "You are not running as the root user.  Please try again with root privileges.";
    logger -t You are not running as the root user.  Please try again with root privileges.
    exit 1;
fi;

hasDSA='';
dsaStatus='';
dsmRegion='';
dsTenantGUID='';

echo "This is a Vanilla bash script to check for ds_agent health associated with Trend Micro Cloud One Workload Security."
echo "Note: This script is not tested for CloudFormation user-data readiness."
logger -t This is a Vanilla bash script to check for ds_agent health associated with Trend Micro Cloud One Workload Security. Note: This script is not tested for CloudFormation user-data readiness.

echo "Looking for local agent..."
if [[ -f /opt/ds_agent/dsa_query ]]; then
    hasDSA=1    
    dsaStatus=`/opt/ds_agent/dsa_query -c GetAgentStatus | grep AgentStatus.agentState | awk '{print $2}'`
    dsmRegion=`/opt/ds_agent/dsa_query -c GetAgentStatus | grep AgentStatus.dsmUrl | awk '{split($2,url,"."); print url[3]}'`
    dsTenantGUID=`/opt/ds_agent/dsa_query -c G≈etAgentStatus | grep AgentStatus.dsmDN | awk '{split($2,dn,"/"); print dn[2]}' | awk '{split($1,dn,"="); print dn[2]}'`

    ${verbose} && echo "DS Agent Status: ${dsaStatus}"
    ${verbose} && echo "DS Region: ${dsmRegion}"
    ${verbose} && echo "DS Tenant GUID: ${dsTenantGUID}"
fi

# Check for ds_agent status first
if [[ $hasDSA == 1 ]]; then
    if [[ $dsaStatus == "green" ]]; then
        echo "All OK"
        logger -t All OK
        exit 0;
    else
        echo "Deep Security Agent is not fully operational. Check the Workload Security Manager for more info."
        logger -t Deep Security Agent is not fully operational. Check the Workload Security Manager for more info.
    fi
fi

# Has ds_agent, but not operational
if [[ $hasDSA == 1 && $dsaStatus != "green" ]]; then

    MANAGERURL='https://workload.'${dsmRegion}'.cloudone.trendmicro.com:443'
    ACTIVATIONURL='dsm://agents.workload.'${dsmRegion}'.cloudone.trendmicro.com:443/'

    ${verbose} && echo "DS Manager URL: ${MANAGERURL}"
    ${verbose} && echo "DS Activation URL: ${ACTIVATIONURL}"

    if ! type curl >/dev/null 2>&1; then
        echo "Please install CURL before running this script."
        logger -t Please install CURL before running this script.
        exit 1;
    fi

    ${verbose} && echo "Using cURL.. curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;"

    CURLOUT=$(eval curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)

    err=$?
    if [[ $err -eq 60 ]]; then
        echo "TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center."
        logger -t TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
        exit 1;
    fi

    if [ -s /tmp/PlatformDetection ]; then
        . /tmp/PlatformDetection
    else
        echo "Failed to download the agent installation support script."
        logger -t Failed to download the Deep Security Agent installation support script.
        exit 1;
    fi

    platform_detect
    if [[ -z "${linuxPlatform}" ]] || [[ -z "${isRPM}" ]]; then
        echo "Unsupported platform is detected."
        logger -t Unsupported platform is detected.
        exit 1;
    fi

    ${verbose} && echo "Linux Platform: ${linuxPlatform}"
    ${verbose} && echo "isRPM: ${isRPM}"

    dsDeploymentToken=$(eval curl -X POST -L $MANAGERURL/api/agentdeploymentscripts -d '{"platform": "linux","validateCertificateRequired": false,"validateDigitalSignatureRequired": false,"activationRequired": true}' $HEADERS $CURLOPTIONS | jq --raw-output '.scriptBody' | tail -n 1 | awk '{split($0,dsToken,"token:"); print dsToken[2]}' | awk '{split($0,dsToken," "); print dsToken[1]}' | awk '{print substr($0,1,length($0)-1)}')

    ${verbose} && echo "DS Deployment Token: ${dsDeploymentToken}" 

    # Reset the ds_agent, for good measure
    /opt/ds_agent/dsa_control -r
    # Activate the ds_agent
    /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}" "policyid:${dsPolicyId}"
fi

# Infer no ds_agent installed
if [[ $hasDSA != 1 ]]; then

    if [[ -z "${dsApiKey}" ]]; then
        echo "Api Key parameter was not passed when running this script. Retry this script with: sudo ./agent_health_status.sh <your-api-key>."
        logger -t Api Key parameter was not passed when running this script. Retry this script with: sudo ./agent_health_status.sh <your-api-key>.
        exit 1;
    fi

    apiKeyId=`echo $dsApiKey | awk '{split($1,id,":"); print id[1]}'`    

    if ! type curl >/dev/null 2>&1; then
        echo "Please install CURL before running this script."
        logger -t Please install CURL before running this script.
        exit 1;
    fi

    if ! type jq >/dev/null 2>&1; then
        echo "Please install jq before running this script."
        logger -t Please install jq before running this script.
        exit 1;
    fi

    ACCOUNTURL='https://accounts.cloudone.trendmicro.com/api/apikeys/'${apiKeyId}
    dsmRegion=$(eval curl -L $ACCOUNTURL $CURLOPTIONS $HEADERS | jq '.urn' | awk '{split($1,region,":"); print region[4]}')

    ${verbose} && printf "DS API Key ID: " && obfuprintperc ${apiKeyId}
    ${verbose} && echo "DS Region: ${dsmRegion}"
    ${verbose} && echo "DS Account URL: ${ACCOUNTURL}"

    ACTIVATIONURL='dsm://agents.workload.'${dsmRegion}'.cloudone.trendmicro.com:443/'
    MANAGERURL='https://workload.'${dsmRegion}'.cloudone.trendmicro.com:443'

    ${verbose} && echo "DS Manager URL: ${MANAGERURL}"
    ${verbose} && echo "DS Activation URL: ${ACTIVATIONURL}"

    dsTenantId=$(eval curl -L $MANAGERURL/api/apikeys/current $CURLOPTIONS $HEADERS | jq '.tenantID')
    dsTenantGUID=$(eval curl -L $MANAGERURL/api/apikeys/current $CURLOPTIONS $HEADERS | jq --raw-output '.tenantGUID')

    ${verbose} && echo "DS Tenant ID: ${dsTenantId}"
    ${verbose} && echo "DS Tenant GUID: ${dsTenantGUID}"
    ${verbose} && echo "Using cURL.. curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;"

    CURLOUT=$(eval curl -L $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)
    err=$?
    if [[ $err -eq 60 ]]; then
        echo "TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center."
        logger -t TLS certificate validation for the agent package download has failed. Please check that your Workload Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
        exit 1;
    fi

    if [ -s /tmp/PlatformDetection ]; then
        . /tmp/PlatformDetection
    else
        echo "Failed to download the agent installation support script."
        logger -t Failed to download the Deep Security Agent installation support script.
        exit 1;
    fi

    platform_detect
    if [[ -z "${linuxPlatform}" ]] || [[ -z "${isRPM}" ]]; then
        echo "Unsupported platform is detected."
        logger -t Unsupported platform is detected.
        exit 1;
    fi

    ${verbose} && echo "Linux Platform: ${linuxPlatform}"
    ${verbose} && echo "isRPM: ${isRPM}"

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
        echo "Failed to download the agent package. Please make sure the package is imported in the Workload Security Manager."
        logger -t Failed to download the agent package. Please make sure the package is imported in the Workload Security Manager
        exit 1;
    fi

    if [[ ${rc} != 0 ]]; then
        echo "Failed to install the agent package."
        logger -t Failed to install the agent package.
        exit 1;
    fi

    echo "Install the agent package successfully."
    logger -t Install the agent package successfully.

    dsDeploymentToken=$(eval curl -X POST -L $MANAGERURL/api/agentdeploymentscripts -d '{"platform": "linux","validateCertificateRequired": false,"validateDigitalSignatureRequired": false,"activationRequired": true}' $HEADERS $CURLOPTIONS | jq --raw-output '.scriptBody' | tail -n 1 | awk '{split($0,dsToken,"token:"); print dsToken[2]}' | awk '{split($0,dsToken," "); print dsToken[1]}' | awk '{print substr($0,1,length($0)-1)}')

    ${verbose} && echo "DS Deployment Token: ${dsDeploymentToken}"

    sleep 15
    /opt/ds_agent/dsa_control -r
    /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}" "policyid:${dsPolicyId}"
    # /opt/ds_agent/dsa_control -a dsm://agents.workload.${dsmRegion}.cloudone.trendmicro.com:443/ "tenantID:${dsTenantGUID}" "token:${dsDeploymentToken}" "policyid:${dsPolicyId}"
fi