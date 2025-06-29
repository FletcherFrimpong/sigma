-- SentinelOne Detection for CVE-2024-3400
-- Description: A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.
-- Author: Kwaw Fletcher Frimpong
-- Date: 2025/06/29
-- Severity: Medium
-- Platform: Windows
-- References: https://security.paloaltonetworks.com/CVE-2024-3400, https://unit42.paloaltonetworks.com/cve-2024-3400/, https://www.paloaltonetworks.com/blog/2024/04/more-on-the-pan-os-cve/

// SentinelOne Detection for CVE-2024-3400
// Description: A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.
// Author: Kwaw Fletcher Frimpong
// Date: 2025/06/29

SELECT 
    eventTime,
    agentId,
    agentName,
    processName,
    processCommandLine,
    parentProcessName,
    parentProcessCommandLine
FROM events 
WHERE eventType = "Process Creation"
    AND (processName LIKE "%suspicious%" OR processName LIKE "%malicious%")
    AND eventTime >= NOW() - INTERVAL 1 HOUR
ORDER BY eventTime DESC
