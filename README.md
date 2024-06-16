# Python Vulnerability Detection Tool
## DESIGN OF ALGORITHMS USING PYTHON 2021/2022


**Introduction**

Software security vulnerabilities are weaknesses in software that can be exploited by attackers to gain unauthorized access to resources. These vulnerabilities are a global concern, with over 22,000 being identified in 2021 alone. A significant class of these vulnerabilities, known as code injections, arises when user input influences the parameters of security-sensitive functions. This can lead to unexpected behavior and potential system compromise.

The goal of this project is to develop a tool that detects vulnerabilities in Python programs by tracing illegal information flows from sources (user inputs) to sinks (sensitive functions) that are not properly sanitized. Although the focus is on a subset of the Python language, the principles can be applied more broadly. This project provides an opportunity to practice Python programming and apply knowledge of data structures and algorithms, while also learning about software security principles.


**Overall Functionality of the Tool**

The tool is designed to detect security vulnerabilities in Python programs by analyzing code slices that represent relevant information flows. It takes as input a Python program and vulnerability patterns, which specify:

- The name of the vulnerability (e.g., SQL injection)
- Sources: functions that act as entry points (e.g., get)
- Sanitizers: functions that neutralize the vulnerability (e.g., escape)
- Sinks: sensitive functions that need protection (e.g., execute)

The tool's functionality includes:

- Input Parsing: Receiving Python code slices and vulnerability patterns.
- Information Flow Analysis: Tracing the flow of information from sources to sinks, identifying any paths that are not sanitized.
- Vulnerability Reporting: Generating reports on detected vulnerabilities, specifying the type, source, and sink involved.

**Commands**

The tool is callable from the command line without any arguments:

_bash_
$ python ./Security.py

After running the command, the tool enters a cycle where it waits for a new command and executes it until a command to exit the program is given. The possible commands are as follows:

- **p file_name:** Read a new Python program slice to analyze from the file file_name.
- **b file_name:** Read new base vulnerability patterns from the file file_name.
- **e json_pattern:** Extend base vulnerabilities with json_pattern.
- **d vuln_name:** Delete vulnerability pattern vuln_name from the base.
- **c:** Show the current program slice and vulnerability patterns.
- **x:** Exit the program.

**Vulnerability Patterns**

The following example illustrates the representation in format in JSON of a list of vulnerability patterns output that contain two patterns as JSON objects:

[

    {
    
        "vulnerability": "SQL injection A",
        
        "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm"],
        
        "sanitizers": ["mogrify", "escape_string"],
        
        "sinks": ["execute"]
        
    },
    
    {
    
        "vulnerability": "SQL injection B",
        
        "sources": ["QueryDict", "ContactMailForm", "ChatMessageForm", "copy"],
        
        "sanitizers": ["mogrify", "escape_string"],
        
        "sinks": ["raw", "RawSQL"]
        
    }

]

**Requirements**

The following Python modules are required to run the tool. These dependencies are listed in the requirements.txt file:

- asyncore
- contextvars
- os
- json
- copy
- re
- tkinter
- To install these dependencies, run:

_bash_
pip install -r requirements.txt
