# APCWatch Plugin Documentation

## Overview

The **APCWatch** plugin for Volatility 3 is designed to detect and analyze Asynchronous Procedure Calls (APCs) within a Windows memory image. APCs are functions scheduled to execute asynchronously in the context of a specific thread, either in user mode or kernel mode. They are commonly used for legitimate purposes but can also be exploited by malicious actors for process injection and code execution.

## Purpose

The primary goal of APCWatch is to identify and enumerate APCs across all processes in a Windows memory dump. By analyzing APCs, investigators can uncover potential indicators of compromise, such as unauthorized code execution or process manipulation. This plugin aids in detecting both system-generated and user-generated APCs, providing insights into the execution flow within the system.

## Functionality

APCWatch operates by traversing the list of processes and their associated threads, extracting detailed information about each APC found. For each APC, the plugin retrieves:

- **Process Name**: The name of the process containing the APC.
- **PID (Process ID)**: The unique identifier of the process.
- **TID (Thread ID)**: The unique identifier of the thread associated with the APC.
- **KernelRoutine**: The address of the kernel-mode APC routine.
- **NormalRoutine**: The address of the user-mode APC routine.
- **APCMode**: Indicates whether the APC is kernel-mode or user-mode.
- **Inserted**: Flag indicating if the APC is currently inserted in the APC queue.
- **KernelAPC**: Flag indicating if a kernel-mode APC is in progress.
- **SpecialAPC**: Flag indicating if a special APC is in progress.
- **KernelAPCPending**: Flag indicating if a kernel-mode APC is pending.
- **UserAPCPending**: Flag indicating if a user-mode APC is pending.

This data that is shown to the user facilitates the detection of anomalous or unauthorized APCs that may signify malicious activity.

## Usage

To utilize the APCWatch plugin, execute the following command within the Volatility 3 framework:


```bash
volatility3 -f [memory_dump] windows.apcwatch.APCWatch
```

Replace `[memory_dump]` with the path to your Windows memory image. The plugin will process the image and display a table of detected APCs, including the details mentioned above.

## Requirements

APCWatch requires the following:

- **Volatility 3 Framework**: Version 2.4.0 or higher.
- **Windows Kernel Module**: The memory image must include the Windows kernel module for accurate analysis.

These requirements ensure that APCWatch can effectively parse and analyze the necessary structures within the memory image.

## Development and Contribution

APCWatch was developed to enhance memory forensics capabilities within the Volatility 3 framework. Its focus on APC analysis provides a valuable tool for identifying sophisticated malware techniques that exploit Windows' asynchronous execution mechanisms.

Contributions to APCWatch are welcome. To contribute:

1. **Fork the Repository**: Create a personal copy of the Volatility 3 repository.
2. **Create a Feature Branch**: Develop your changes in a dedicated branch.
3. **Implement Changes**: Add or modify code as necessary, ensuring adherence to coding standards.
4. **Write Tests**: Develop tests to validate your changes.
5. **Submit a Pull Request**: Propose your changes for inclusion in the main repository.

Detailed guidelines for contributing can be found in the Volatility 3 contribution documentation.

## References

- [Asynchronous Procedure Calls - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
- [Understanding Windows Asynchronous Procedure Calls](https://www.codeproject.com/Articles/5355373/Understanding-Windows-Asynchronous-Procedure-Calls)
- [Asynchronous Procedure Call - Red Team Notes 2.0](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1055-process-injection/asynchronous-procedure-call)

These resources provide in-depth information on APCs and their role in Windows operating systems.

## Conclusion

The APCWatch plugin is a valuable tool for forensic investigators seeking to analyze APCs within Windows memory images. By providing detailed insights into APCs, APCWatch aids in the detection of both legitimate and malicious activities, enhancing the overall effectiveness of memory forensic analyses.