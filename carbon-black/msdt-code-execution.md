# MSDT Suspicious Code Execution

## Description

In May 2022, CVE-2022-30190 (named Follina) was issued by Microsoft regarding the Microsoft Support Diagnostic Tool (MSDT) in Windows vulnerability. The exploit is a remote code execution vulnerability that exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker can exploit this vulnerability and run arbitrary code with the privileges of the calling application. 

## Response

Determine the legitimacy of the activity by checking the command-line arguments passed to msdt.exe. Look for base64 encoded commands, powershell.exe, cmd.exe, and other script interpreters.

## Detection

```
(process_name:msdt.exe) AND (process_cmdline:*PCWDiagnostic* AND process_cmdline:IT_BrowseForFile*)
```

## References
 - https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
 - https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/
 - https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug
 - https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/
