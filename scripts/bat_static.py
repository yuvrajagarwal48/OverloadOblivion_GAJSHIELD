#!/usr/bin/env python3
"""
Batch File Malware Detector
A static analysis tool to identify suspicious patterns in Windows batch (.bat) files
"""

import os
import re
import sys
import hashlib
import logging
import math
from collections import Counter
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class BatchFileAnalyzer:
    def __init__(self, file_path=None, verbose=False):
        """
        Initialize the analyzer with a file path
        
        Args:
            file_path (str, optional): Path to the batch file to analyze
            verbose (bool): Enable verbose output
        """
        self.file_path = file_path
        self.verbose = verbose
        self.content = ""
        self.lines = []
        self.file_hash = {
            "md5": "",
            "sha1": "",
            "sha256": ""
        }
        self.suspicious_score = 0
        self.detection_results = []
        
        # Use default sample file if none provided
        if self.file_path is None:
            # Look for .bat files in the current directory
            for file in os.listdir('.'):
                if file.lower().endswith('.bat'):
                    self.file_path = os.path.abspath(file)
                    logger.info(f"Using default file: {self.file_path}")
                    break
            
            if self.file_path is None:
                sample_path = os.path.join(os.path.dirname(__file__), '..', 'samples')
                if os.path.exists(sample_path):
                    for file in os.listdir(sample_path):
                        if file.lower().endswith('.bat'):
                            self.file_path = os.path.join(sample_path, file)
                            logger.info(f"Using default file: {self.file_path}")
                            break
            
        # Define suspicious patterns commonly found in malicious batch files
        self.suspicious_patterns = {
            # Obfuscation techniques
            "obfuscation": [
                r"set\s+[a-zA-Z0-9_]+=%[a-zA-Z0-9_]+:~[0-9]+,[0-9]+%", # String manipulation/obfuscation
                r"echo\s+off\s*&\s*cls",  # Hide console output
                r"@echo\s+off",           # Suppress command echo
                r"\^",                    # Escape character for obfuscation
                r"set\s+[a-zA-Z0-9_]+=.*!.*!",  # Variable expansion obfuscation
                r"::.*[a-zA-Z0-9]+",      # Comments that hide code
                r"goto\s+:[a-zA-Z0-9]+",  # Multiple goto jumps (obfuscation)
                r"color\s+[0-9a-f]{2}",   # Change console color
                r"chcp\s+[0-9]+",         # Change code page (obfuscation)
            ],
            
            # System modification
            "system_modification": [
                r"reg\s+add",             # Registry modification
                r"reg\s+delete",          # Registry deletion
                r"regsvr32",              # Register/unregister DLLs
                r"attrib\s+[+]h",         # Hide files
                r"attrib\s+[+]s",         # System attribute
                r"attrib\s+[+]r",         # Read-only attribute
                r"schtasks\s+/create",    # Create scheduled task
                r"net\s+user\s+.+\s+/add",  # Add user
                r"net\s+localgroup\s+administrators",  # Modify admin group
                r"icacls.*\/grant",       # Change file permissions
                r"takeown",               # Take ownership of files
            ],
            
            # Network activity
            "network": [
                r"powershell.*wget",      # PowerShell download
                r"powershell.*invoke-webrequest", # PowerShell download
                r"powershell.*downloadstring", # PowerShell download and execute
                r"powershell.*downloadfile", # PowerShell download
                r"certutil.*-urlcache",   # Download using certutil
                r"bitsadmin.*transfer",   # Download using bitsadmin
                r"curl\s+-o",             # Download using curl
                r"wget\s+-O",             # Download using wget
                r"nc\s+-[l]*\s+[0-9]+",   # Netcat listener
                r"nslookup",              # DNS lookups
                r"net\s+use",             # Network resource connection
                r"ipconfig|ifconfig",     # Network configuration
            ],
            
            # Payload execution
            "execution": [
                r"powershell\s+-e",       # Base64 encoded PowerShell
                r"powershell\s+-enc",     # Base64 encoded PowerShell
                r"powershell\s+-nop",     # No profile PowerShell
                r"powershell\s+-exec bypass",  # ExecutionPolicy bypass
                r"rundll32",              # Run DLL code
                r"regsvr32\s+/s\s+/u\s+/i", # Regsvr32 with ScriptletURL
                r"wmic\s+.*\s+call\s+create", # WMI process creation
                r"mshta\s+.*\s+javascript", # Mshta execution
                r"cscript|wscript",       # Script execution
                r"cmd\s+/c",              # Command execution
                r"start\s+/b",            # Background execution
                r"shell\s*execute",       # Shell execute
            ],
            
            # Persistence
            "persistence": [
                r"reg.*run",              # Run keys
                r"reg.*runonce",          # RunOnce keys 
                r"startup",               # Startup folder
                r"schtasks",              # Scheduled tasks
                r"wmic\s+.*\s+call\s+create", # WMI persistence
                r"at\s+[0-9]{2}:[0-9]{2}", # Scheduled execution
            ],
            
            # Evasion techniques
            "evasion": [
                r"timeout\s+/t\s+[0-9]+", # Delay execution
                r"ping\s+127.0.0.1\s+-n", # Delay using ping
                r"choice\s+/c\s+yn\s+/d\s+y\s+/t\s+[0-9]+", # Delay using choice
                r"tasklist",              # Process enumeration
                r"findstr",               # String searching (for evasion)
                r"if\s+not\s+exist",      # Condition for AV evasion
                r"if\s+exist\s+.*goto",   # Condition for AV evasion
                r"wmic\s+process",        # Process enumeration
            ],
            
            # Data theft and destruction
            "data": [
                r"type\s+.*\s*>\s*",      # File output redirection
                r"find\s+/i\s+\"password\"", # Password hunting
                r"findstr\s+/i\s+\"password\"", # Password hunting
                r"copy\s+.*\s+.*\.exe",   # Executable copying
                r"del\s+/[a-zA-Z]*\s+/[a-zA-Z]*", # File deletion
                r"rmdir\s+/[a-zA-Z]*\s+/[a-zA-Z]*", # Directory deletion
                r"for\s+/r\s+.*\s+do",    # Recursive for loop (file operations)
                r"forfiles",              # File operations
                r"xcopy\s+/[a-zA-Z]*",    # File copying
                r"robocopy",              # Robust file copying
            ],
            
            # Dangerous commands
            "dangerous": [
                r"format\s+[a-zA-Z]:",    # Format drive
                r"shutdown\s+/[a-zA-Z]",  # System shutdown
                r"taskkill\s+/f\s+/im",   # Force kill processes
                r"sc\s+stop",             # Stop services
                r"sc\s+config",           # Reconfigure services
                r"sc\s+delete",           # Delete services
                r"rd\s+/s\s+/q",          # Recursive directory deletion
                r"cacls",                 # Change ACLs
                r"net\s+stop",            # Stop services
                r"cipher\s+/w:",          # Wipe free space
                r"vssadmin\s+delete",     # Delete shadow copies
            ]
        }

        # Particularly high-risk patterns that can indicate immediate threats
        self.critical_patterns = [
            r"powershell\s+-e\s+[a-zA-Z0-9/+=]{40,}", # Long base64 encoded commands
            r"certutil\s+-decode",        # Decode base64 files
            r"mshta\s+http",              # Remote HTA execution
            r"bitsadmin.*download",       # Download using bitsadmin
            r"wmic\s+process\s+call\s+create", # Process creation via WMI
            r"vssadmin\s+delete\s+shadows", # Delete shadow copies (ransomware)
            r"bcdedit.*recoveryenabled\s+no", # Disable recovery (ransomware)
            r"wbadmin\s+delete\s+catalog", # Delete backups (ransomware)
            r"Invoke-Expression\s+\(New-Object\s+Net\.WebClient\)", # PowerShell download and exec
            r"downloadstring|downloadfile|invoke-webrequest", # PowerShell web download
            r"Set-MpPreference\s+-DisableRealtimeMonitoring", # Disable Windows Defender
            r"Add-MpPreference\s+-ExclusionPath", # Add exclusion to Windows Defender
        ]
        
        # Known innocent patterns that might generate false positives
        self.innocent_patterns = [
            r"echo\s+Hello",              # Simple echo
            r"title\s+",                  # Set window title
            r"cd\s+",                     # Change directory
            r"dir\s+",                    # List directory
            r"set\s+path=",               # Set path environment variable
            r"rem\s+",                    # Remarks
            r"pause",                     # Pause execution (common in legitimate scripts)
            r"cls",                       # Clear screen
            r"color\s+07",                # Default color
        ]
        
    def calculate_file_hashes(self):
        """Calculate MD5, SHA1, and SHA256 hashes of the file"""
        if not self.file_path or not os.path.exists(self.file_path):
            return False
            
        try:
            with open(self.file_path, 'rb') as file:
                content = file.read()
                self.file_hash["md5"] = hashlib.md5(content).hexdigest()
                self.file_hash["sha1"] = hashlib.sha1(content).hexdigest()
                self.file_hash["sha256"] = hashlib.sha256(content).hexdigest()
            return True
        except Exception as e:
            logger.error(f"Error calculating file hashes: {str(e)}")
            return False
            
    def read_file(self):
        """Read the batch file content"""
        if not self.file_path or not os.path.exists(self.file_path):
            logger.error("No valid batch file provided for analysis")
            return False
            
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as file:
                self.content = file.read()
                self.lines = self.content.split('\n')
            return True
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            return False
            
    def analyze(self):
        """
        Analyze the batch file for suspicious patterns
        
        Returns:
            dict: Analysis report if successful, None otherwise
        """
        if not self.read_file():
            return None
        
        self.calculate_file_hashes()
        
        # Check file size (suspiciously large batch files)
        file_size = os.path.getsize(self.file_path)
        if file_size > 100000:  # 100KB
            self.suspicious_score += 10
            self.detection_results.append(("SUSPICIOUS", "Unusually large batch file", "File size exceeds 100KB"))
            
        # Check for high number of lines (suspicious complexity)
        if len(self.lines) > 200:
            self.suspicious_score += 5
            self.detection_results.append(("SUSPICIOUS", "High complexity", f"File contains {len(self.lines)} lines"))
            
        # Calculate the entropy of the file to detect obfuscation
        content_entropy = self._calculate_entropy(self.content)
        if content_entropy > 5.5:  # High entropy threshold
            self.suspicious_score += 15
            self.detection_results.append(("SUSPICIOUS", "High entropy", f"Entropy value: {content_entropy:.2f} suggests possible obfuscation"))
        
        # Check for critical patterns
        for pattern in self.critical_patterns:
            matches = re.finditer(pattern, self.content, re.IGNORECASE)
            for match in matches:
                self.suspicious_score += 30
                line_num = self.content[:match.start()].count('\n') + 1
                self.detection_results.append(("CRITICAL", f"Critical pattern found on line {line_num}", match.group(0)))
        
        # Check for suspicious patterns
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, self.content, re.IGNORECASE)
                for match in matches:
                    # Check if this match overlaps with an innocent pattern
                    innocent = False
                    for innocent_pattern in self.innocent_patterns:
                        innocent_matches = re.finditer(innocent_pattern, self.content, re.IGNORECASE)
                        for innocent_match in innocent_matches:
                            if (match.start() >= innocent_match.start() and match.start() <= innocent_match.end()) or \
                               (match.end() >= innocent_match.start() and match.end() <= innocent_match.end()):
                                innocent = True
                                break
                    
                    if not innocent:
                        line_num = self.content[:match.start()].count('\n') + 1
                        score = 5 if category != "obfuscation" else 10
                        self.suspicious_score += score
                        self.detection_results.append(
                            ("WARNING", f"Suspicious {category} pattern on line {line_num}", match.group(0))
                        )
        
        # Generate and return the report
        return self.generate_report()
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy for a string"""
        if not data:
            return 0
        
        entropy = 0
        char_count = Counter(data)
        for count in char_count.values():
            probability = count / len(data)
            entropy -= probability * (math.log(probability, 2) if probability > 0 else 0)
        return entropy
            
    def get_risk_level(self):
        """Return risk level based on suspicious score"""
        if self.suspicious_score >= 70:
            return "MALICIOUS"
        elif self.suspicious_score >= 40:
            return "HIGH RISK"
        elif self.suspicious_score >= 20:
            return "MEDIUM RISK"
        elif self.suspicious_score >= 5:
            return "LOW RISK"
        else:
            return "CLEAN"
    
    def generate_report(self):
        """Generate analysis report"""
        risk_level = self.get_risk_level()
        
        # If no file path is available, create a placeholder
        filename = os.path.basename(self.file_path) if self.file_path else "unknown.bat"
        filepath = self.file_path if self.file_path else "unknown"
        filesize = os.path.getsize(self.file_path) if self.file_path and os.path.exists(self.file_path) else 0
        
        report = {
            "filename": filename,
            "path": filepath,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": filesize,
            "hashes": self.file_hash,
            "risk_level": risk_level,
            "suspicious_score": self.suspicious_score,
            "findings": self.detection_results
        }
        
        return report
    
    def print_report(self, report):
        """Print the analysis report to the console"""
        if not report:
            logger.error("No report available to print")
            return
            
        print("\n" + "="*80)
        print(f"BATCH FILE ANALYSIS REPORT")
        print("="*80)
        print(f"File: {report['filename']}")
        print(f"Path: {report['path']}")
        print(f"Analysis Time: {report['analysis_time']}")
        print(f"File Size: {report['file_size']} bytes")
        print("-"*80)
        print("File Hashes:")
        print(f"  MD5:    {report['hashes']['md5']}")
        print(f"  SHA1:   {report['hashes']['sha1']}")
        print(f"  SHA256: {report['hashes']['sha256']}")
        print("-"*80)
        print(f"Risk Level: {report['risk_level']} (Score: {report['suspicious_score']})")
        print("-"*80)
        print("Findings:")
        
        if not report['findings']:
            print("  No suspicious patterns detected")
        else:
            # Group findings by severity
            findings_by_severity = {"CRITICAL": [], "WARNING": [], "SUSPICIOUS": []}
            for severity, message, pattern in report['findings']:
                findings_by_severity[severity].append((message, pattern))
            
            # Print critical findings first
            if findings_by_severity["CRITICAL"]:
                print("\n  CRITICAL FINDINGS:")
                for message, pattern in findings_by_severity["CRITICAL"]:
                    print(f"  - {message}")
                    if self.verbose:
                        print(f"    Pattern: {pattern}")
            
            # Print warnings
            if findings_by_severity["WARNING"]:
                print("\n  WARNINGS:")
                for message, pattern in findings_by_severity["WARNING"]:
                    print(f"  - {message}")
                    if self.verbose:
                        print(f"    Pattern: {pattern}")
            
            # Print suspicious patterns
            if findings_by_severity["SUSPICIOUS"]:
                print("\n  SUSPICIOUS PATTERNS:")
                for message, pattern in findings_by_severity["SUSPICIOUS"]:
                    print(f"  - {message}")
                    if self.verbose:
                        print(f"    Pattern: {pattern}")
        
        print("="*80)
        
        # Print recommendation based on risk level
        if report['risk_level'] in ["MALICIOUS", "HIGH RISK"]:
            print("RECOMMENDATION: This file exhibits strong characteristics of malware.")
            print("                Isolate and do not execute this file.")
        elif report['risk_level'] == "MEDIUM RISK":
            print("RECOMMENDATION: This file contains suspicious elements that may be malicious.")
            print("                Review the script contents carefully before execution.")
        elif report['risk_level'] == "LOW RISK":
            print("RECOMMENDATION: This file contains some patterns that could be suspicious.")
            print("                Review the script contents before execution.")
        else:
            print("RECOMMENDATION: No clearly malicious patterns detected, but always review scripts")
            print("                before execution as a security best practice.")
        
        print("="*80 + "\n")

# # Example usage
# if __name__ == "__main__":
#     # Import math here to avoid unnecessary import if the script exits early
#     import math
    
#     try:
#         file_path = sys.argv[1] if len(sys.argv) > 1 else None
#         analyzer = BatchFileAnalyzer(file_path, verbose=True)
#         report = analyzer.analyze()
        
#         if report:
#             analyzer.print_report(report)
#             print("\nReport as JSON:")
#             import json
#             print(json.dumps(report, indent=2))
#         else:
#             print("Analysis failed - no report generated")
#     except Exception as e:
#         logger.error(f"Error during analysis: {e}")
#         print(f"Analysis failed: {str(e)}")