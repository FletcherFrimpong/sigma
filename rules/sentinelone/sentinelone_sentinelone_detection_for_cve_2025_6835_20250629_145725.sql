-- SentinelOne Detection for CVE-2025-6835
-- Description: A vulnerability was found in code-projects Library System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /student-issue-book.php. The manipulation of the argument reg leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.
-- Author: Kwaw Fletcher Frimpong
-- Date: 2025/06/29
-- Severity: Medium
-- Platform: Windows
-- References: https://code-projects.org/, https://github.com/blueandhack/cve/issues/6, https://vuldb.com/?ctiid.314279

// SentinelOne Detection for CVE-2025-6835
// Description: A vulnerability was found in code-projects Library System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /student-issue-book.php. The manipulation of the argument reg leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.
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
