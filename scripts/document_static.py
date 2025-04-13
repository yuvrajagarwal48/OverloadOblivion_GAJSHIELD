#!/usr/bin/env python3
"""
Document Malware Scanner
A tool for detecting malicious content in document files using YARA rules
"""

import os
import sys
import time
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("doc_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Supported file types
SUPPORTED_EXTENSIONS = {
    '.rtf': 'RTF document',
    '.doc': 'Microsoft Word document',
    '.docx': 'Microsoft Word document (OOXML)',
    '.xls': 'Microsoft Excel spreadsheet',
    '.xlsx': 'Microsoft Excel spreadsheet (OOXML)',
    '.ppt': 'Microsoft PowerPoint presentation',
    '.pptx': 'Microsoft PowerPoint presentation (OOXML)',
    '.pdf': 'PDF document'
}

# Default YARA rules as a string - fixed syntax issues
DEFAULT_YARA_RULES = """
private rule isRTF {
    strings:
        $magic_rtf = /^\\s*{\\\\rt/
    condition:
        $magic_rtf and filesize < 25MB
}

rule suspicious_RTF_1 {
    meta:
        description = "Rule to detect suspicious RTF files using known exploits (or) potentially dangerous commands"
        author = "Loginsoft Research Unit"
        date = "2020-05-25"
        reference_1 = "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/fileformat/office_ms17_11882.rb#L85"
        reference_2 = "https://github.com/embedi/CVE-2017-11882/tree/master/example"
        hash = "6fe87a14b97a5885a341e29e1b923e9c"
        tested = "https://www.hybrid-analysis.com/yara-search/results/a6212320f1e62190c235b6d953fb3a136f279cecc3ad468fde4c2c7b87140bec"
        
    strings:
        $suspicious_1 = { 45 71 75 61 74 69 6F 6E 2E 33 } // check for 'Equation.3'
        $suspicious_2 = { 30 61 30 31 30 38 35 61 35 61}  // check for 'font' address where the overflow occurs i.e; 0a01085a5a
        $suspicious_3 = "4d6963726f736f6674204571756174696f6e20332e30" ascii  // check for 'Microsoft Equation' 
        $suspicious_4 = { 50 61 63 6b 61 67 65 } //check for 'package' keyword along with 'Equation.3 (this is gives false positives)'
        $suspicious_5 = "0002CE020000000000C000000000000046" ascii nocase  //check for CLSID, commonly found in Metasploit exploit (ms_17_11882) 
        $suspicious_6 = "objclass" ascii nocase
    condition:
        isRTF and 
        4 of ($suspicious_*) and 
        ($suspicious_2 and $suspicious_5)
}

rule suspicious_RTF_2 {
    meta:
        description = "Rule to detect suspicious RTF files potentially dangerous commands/function"
        author = "Loginsoft Research Unit"
        date = "2020-05-25"
        hash = "d63a4d81fc43316490d68554bcfba373"
        hash = "65cb82f6853bf16f925942c7e00119d6"
        hash = "a0e6933f4e0497269620f44a083b2ed4"
        tested = "https://www.hybrid-analysis.com/yara-search/results/0af96a529de7c51d4ac526a1e454e3730566bdb6f3789dedec344d1b185c3e53"
    strings:
      $suspicious_1 = "objupdate" nocase ascii                  // This forces the embedded object to update before it's displayed
      $suspicious_2 = /4571[a-zA-Z0-9]+(e|E)2["",(e|E)33]/      // check for Hex encoded form of 'Equation.3' header
      $suspicious_3 = /(90){3,20}/ // check for Nop sledging
      $suspicious_4 = "6d73687461" nocase ascii  //check for mshta bin
    condition:
        isRTF and 
        $suspicious_1 and (2 of ($suspicious*))
}

rule suspicious_RTF_withShellCode {
    meta:
        author = "Rich Warren"
        description = "Attempts to exploit CVE-2017-11882 using Packager"
        reference = "https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py"
        tested = "https://www.hybrid-analysis.com/yara-search/results/89b278531c28b674f23f46b2584c649801f27979be810c1754fdadf6c6081f88"
        hash = "65cb82f6853bf16f925942c7e00119d6"
        hash = "a0e6933f4e0497269620f44a083b2ed4"
    strings:    
        $suspicious_1 = { 45 71 75 61 74 69 6F 6E 2E 33 }
        $suspicious_2 = { 50 61 63 6b 61 67 65 }
        $suspicious_3 = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase
        $suspicious_4 = "objclass" ascii nocase
        $suspicious_5 = "6d73687461" nocase ascii  //check for mshta binary
    condition:
        isRTF and $suspicious_3 and 2 of them 
}

rule suspicious_RTF_usingURLMoniker {
    meta:
        author = "Loginsoft Research Unit"
        description = "Detecting malicious files which leverage URLMoniker with HTTP request"
        reference = "https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html"
        reference = "https://blog.nviso.eu/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
        sample = "https://github.com/SyFi/cve-2017-0199"
        date = "2020-06-01"        
        tested = "https://www.hybrid-analysis.com/yara-search/results/c55846e3f40e6ee6e87cfdb942653c738d299298e305b21ed4050d8d189faa81"
    strings:
        $objdata = "objdata 0105000002000000" nocase
        $urlmoniker = "E0C9EA79F9BACE118C8200AA004BA90B" nocase
        $http = "68007400740070003a002f002f00" nocase
        $http1 = "http" nocase wide
    condition:
        isRTF and 
        ($objdata and $urlmoniker) or 
        ($urlmoniker and (1 of ($http*))) or 
        ($objdata and (1 of ($http*)))
}

rule suspicious_RTF_CVE_2018_0802 {
    meta:
        author = "Rich Warren"
        reference = "https://github.com/rxwx/CVE-2018-0802/blob/master/yara/rtf_CVE_2018_0802.yara"
        reference = "https://research.checkpoint.com/2018/another-office-equation-rce-vulnerability/"
        reference = "https://www.fireeye.com/blog/threat-research/2019/06/government-in-central-asia-targeted-with-hawkball-backdoor.html"
        tested = "https://www.hybrid-analysis.com/yara-search/results/a18c08c8d54df2fd28e019308188dd620c4d6b45b76d87e81fc3bd101ccbb69c"
    strings:
        $objupdate = "objupdate" nocase ascii         // This forces the embedded object to update before it's displayed
        $objdata = "objdata 0105000002000000" nocase // Loginsoft added this string since to produce efficient result. 
        $equation = { 45 71 75 61 74 69 6F 6E 2E 33 } 
        $header_and_shellcode = /03010[0-1]([0-9a-fA-F]){4}([0-9a-fA-F]+08)([0-9a-fA-F]{4})([0-9a-fA-F]{296})2500/ ascii nocase
    condition:
        uint32be(0) == 0x7B5C7274 and isRTF and all of them
}

rule suspicious_DOC_with_Macros {
    meta:
        description = "Detect Office documents with suspicious macro indicators"
        author = "GitHub Copilot"
        date = "2025-04-12"
    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $macro_str1 = "ThisDocument" ascii nocase
        $macro_str2 = "Auto_Open" ascii nocase
        $macro_str3 = "AutoOpen" ascii nocase
        $macro_str4 = "AutoExec" ascii nocase
        $macro_str5 = "Document_Open" ascii nocase
        $suspicious_str1 = "Shell" ascii nocase
        $suspicious_str2 = "WScript.Shell" ascii nocase
        $suspicious_str3 = "powershell" ascii nocase
        $suspicious_str4 = "cmd.exe" ascii nocase
        $suspicious_str5 = "CreateObject" ascii nocase
        $suspicious_str6 = "Process" ascii nocase
    condition:
        $ole_magic at 0 and 
        (2 of ($macro_str*)) and
        (2 of ($suspicious_str*))
}

rule suspicious_PDF_with_JavaScript {
    meta:
        description = "Detect PDF files with suspicious JavaScript"
        author = "GitHub Copilot"
        date = "2025-04-12"
    strings:
        $pdf_magic = "%PDF-"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $js3 = "/Launch" nocase
        $js4 = "/OpenAction" nocase
        $js5 = "/AA" nocase
        $suspicious1 = "eval" nocase
        $suspicious2 = "unescape" nocase
        $suspicious3 = "getAnnots" nocase
        $suspicious4 = "getIcon" nocase
        $suspicious5 = "this.exportDataObject" nocase
        $suspicious6 = "util.printf" nocase
        $suspicious7 = "util.byteToChar" nocase
    condition:
        $pdf_magic at 0 and
        (2 of ($js*)) and
        (2 of ($suspicious*))
}

rule generic_Suspicious_Document_Content {
    meta:
        description = "Generic detection for suspicious content in document files"
        author = "GitHub Copilot"
        date = "2025-04-12"
    strings:
        $url_pattern = /https?:\/\/[a-zA-Z0-9\.\-_]{5,50}\.((xyz)|(top)|(club)|(online)|(site)|(space)|(pw)|(cc)|(icu)|(ru))/ nocase
        $b64_pwsh_pattern1 = /UG93ZXJTaGVsbC/ nocase // PowerShell
        $b64_pwsh_pattern2 = /LUVuY29kZWRDb21tYW5k/ nocase // -EncodedCommand
        $b64_pwsh_pattern3 = /cG93ZXJzaGVsbC5leGU/ nocase // powershell.exe
        $shellcode_pattern1 = { 90 90 90 90 }  // NOP sled
        $susp_path1 = "C:\\ProgramData\\" ascii nocase
        $susp_path2 = "C:\\Users\\Public\\" ascii nocase
        $susp_path3 = "%TEMP%\\" ascii nocase
        $susp_path4 = "%APPDATA%\\" ascii nocase
    condition:
        filesize < 20MB and
        (
            (any of ($url_pattern)) or
            (any of ($b64_pwsh_pattern*)) or
            $shellcode_pattern1 or
            (any of ($susp_path*) and 1 of ($url_pattern,$b64_pwsh_pattern1,$b64_pwsh_pattern2,$b64_pwsh_pattern3))
        )
}
"""

class MalwareScanner:
    """Malware scanner class for document files"""
    
    def __init__(self, rules_path=None, recursive=False, quiet=False, json_output=False):
        """Initialize the scanner with YARA rules"""
        self.rules_path = rules_path
        self.recursive = recursive
        self.quiet = quiet
        self.json_output = json_output
        self.results = []
        
        try:
            # Import yara here to handle import errors better
            try:
                import yara
            except ImportError:
                print(f"{Fore.RED}Error: yara-python package not found. Please install it with 'pip install yara-python'.{Style.RESET_ALL}")
                print("Continuing in limited functionality mode...")
                self.rules = None
                return
                
            # Compile YARA rules from file or use default rules
            if rules_path and os.path.exists(rules_path):
                self.rules = yara.compile(filepath=rules_path)
                logger.info(f"Successfully compiled rules from {rules_path}")
            else:
                # Use default rules if no file provided
                try:
                    self.rules = yara.compile(source=DEFAULT_YARA_RULES)
                    logger.info("Using default built-in YARA rules")
                except Exception as e:
                    print(f"{Fore.RED}Error compiling YARA rules: {e}{Style.RESET_ALL}")
                    # Try to identify the problematic line
                    if hasattr(e, 'message') and 'line' in str(e):
                        line_no = int(str(e).split('line')[1].split(':')[0].strip())
                        lines = DEFAULT_YARA_RULES.split('\n')
                        print(f"{Fore.YELLOW}Problem near line {line_no}:{Style.RESET_ALL}")
                        for i in range(max(0, line_no-3), min(len(lines), line_no+2)):
                            if i == line_no-1:
                                print(f"{Fore.RED}>>> {lines[i]}{Style.RESET_ALL}")
                            else:
                                print(f"    {lines[i]}")
                    
                    print("Will try to continue without YARA scanning...")
                    self.rules = None
                    return
                
            # Display compiled rules information
            self.display_compiled_rules()
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {e}")
            print(f"{Fore.RED}Scanner initialization failed: {e}{Style.RESET_ALL}")
            self.rules = None
    
    def display_compiled_rules(self):
        """Display information about the compiled rules"""
        if not hasattr(self, 'rules') or not self.rules:
            logger.error("No valid YARA rules object")
            return
            
        print(f"\n{Fore.CYAN}=== Compiled YARA Rules ===={Style.RESET_ALL}")
        
        # We'll use a simpler approach to count rules that's less prone to errors
        try:
            # Get the rule names from the YARA rules source
            rule_names = []
            rule_text = DEFAULT_YARA_RULES if not self.rules_path else open(self.rules_path).read()
            
            # Simple regex to find rule names
            import re
            rule_matches = re.finditer(r'(?:private\s+)?rule\s+(\w+)\s*{', rule_text)
            for match in rule_matches:
                rule_name = match.group(1)
                
                # Determine if this is a private rule
                is_private = 'private rule ' + rule_name in rule_text
                
                if is_private:
                    print(f"{Fore.YELLOW}[+] Private Rule: {rule_name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Detection Rule: {rule_name}{Style.RESET_ALL}")
                    
                rule_names.append(rule_name)
            
            print(f"\n{Fore.CYAN}Total: {len(rule_names)} rules compiled successfully{Style.RESET_ALL}\n")
            
        except Exception as e:
            logger.warning(f"Could not display full rule information: {e}")
            print(f"{Fore.YELLOW}Rules compiled successfully, but could not list all rules.{Style.RESET_ALL}\n")
    
    def is_document_file(self, file_path):
        """Check if the file is a supported document type"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # First check extension
        if file_ext in SUPPORTED_EXTENSIONS:
            # Try to verify with file magic if available
            try:
                # Try using python-magic
                try:
                    import magic
                    mime = magic.Magic()
                    file_type = mime.from_file(file_path).lower()
                    
                    # Check if file type matches known document signatures
                    doc_signatures = ['word', 'excel', 'powerpoint', 'rtf', 'pdf', 'ole', 'office', 'document', 'msword']
                    return any(sig in file_type for sig in doc_signatures)
                except ImportError:
                    # If python-magic is not available, trust the extension
                    return True
            except Exception:
                # If file type detection fails, rely on extension
                return True
        return False
    
    def scan_file(self, file_path):
        """Scan a single file with YARA rules"""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File does not exist: {file_path}")
                return None
                
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                logger.warning(f"Skipping {file_path}: File size too large ({file_size/(1024*1024):.2f}MB)")
                return None
                
            start_time = time.time()
            
            result = {
                'file_path': file_path,
                'file_size': file_size,
                'scan_time': 0,
                'matches': []
            }
            
            # Skip YARA scan if rules aren't available
            if hasattr(self, 'rules') and self.rules:
                try:
                    matches = self.rules.match(file_path)
                    scan_time = time.time() - start_time
                    result['scan_time'] = scan_time
                    
                    if matches:
                        for match in matches:
                            rule_info = {
                                'rule': match.rule,
                                'namespace': match.namespace,
                                'tags': match.tags,
                                'meta': match.meta,
                                'strings': [(str(s[0]), s[1], s[2].hex() if isinstance(s[2], bytes) else s[2]) for s in match.strings],
                            }
                            result['matches'].append(rule_info)
                        
                        logger.info(f"Found {len(matches)} suspicious patterns in {file_path}")
                    else:
                        logger.info(f"No suspicious patterns found in {file_path}")
                except Exception as e:
                    logger.error(f"YARA scan error: {e}")
                    print(f"{Fore.RED}YARA scan failed: {e}. Falling back to basic scanning.{Style.RESET_ALL}")
            else:
                # If YARA scanning not available, perform basic checks
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                    # Basic suspicious patterns
                    suspicious_patterns = [
                        b'powershell', b'cmd.exe', b'http://', b'https://',
                        b'eval(', b'ActiveXObject', b'CreateObject',
                        b'Shell', b'WScript.Shell',
                        b'Auto_Open', b'Document_Open', 
                        b'\x90\x90\x90\x90'  # NOP sled
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            rule_info = {
                                'rule': 'basic_pattern_match',
                                'namespace': 'default',
                                'tags': ['basic'],
                                'meta': {'description': 'Basic suspicious pattern detection'},
                                'strings': [(content.find(pattern), 'suspicious_pattern', pattern.hex())],
                            }
                            result['matches'].append(rule_info)
                            logger.info(f"Found basic suspicious pattern in {file_path}")
                            break
                
                scan_time = time.time() - start_time
                result['scan_time'] = scan_time
                
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return None
    
    def scan_path(self, target_path):
        """Scan a file or directory"""
        if os.path.isfile(target_path):
            if self.is_document_file(target_path):
                result = self.scan_file(target_path)
                if result:
                    self.results.append(result)
            else:
                logger.info(f"Skipping {target_path}: Not a supported document file")
                print(f"{Fore.YELLOW}Skipping {target_path}: Not a supported document file{Style.RESET_ALL}")
        
        elif os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_document_file(file_path):
                        result = self.scan_file(file_path)
                        if result:
                            self.results.append(result)
                
                if not self.recursive:
                    break  # Don't recurse into subdirectories
        else:
            logger.error(f"Path {target_path} is not a file or directory")
            print(f"{Fore.RED}Error: Path {target_path} is not a file or directory{Style.RESET_ALL}")

    def print_results(self):
        """Print scan results"""
        import json
        
        if self.json_output:
            print(json.dumps(self.results, indent=2))
            return

        total_files = len(self.results)
        malicious_files = sum(1 for r in self.results if r['matches'])
        
        print("\n" + "="*80)
        print(f"SCAN SUMMARY: {total_files} files scanned, {malicious_files} suspicious files found")
        print("="*80 + "\n")
        
        if self.quiet and malicious_files == 0:
            return
            
        for result in self.results:
            if self.quiet and not result['matches']:
                continue
                
            file_path = result['file_path']
            if result['matches']:
                print(f"{Fore.RED}[SUSPICIOUS] {file_path}{Style.RESET_ALL}")
                for match in result['matches']:
                    print(f"  - Rule: {match['rule']}")
                    
                    # Print meta information
                    if match['meta']:
                        print(f"    Meta:")
                        for key, value in match['meta'].items():
                            print(f"      {key}: {value}")
                    
                    # Print matched strings (limited to avoid overwhelming output)
                    if match['strings']:
                        print(f"    Matched patterns (showing up to 3):")
                        for i, (offset, identifier, matched_bytes) in enumerate(match['strings'][:3]):
                            print(f"      - {identifier} at offset {offset}")
                            
                        if len(match['strings']) > 3:
                            print(f"      ... and {len(match['strings']) - 3} more matches")
                            
                print()
            else:
                print(f"{Fore.GREEN}[CLEAN] {file_path}{Style.RESET_ALL}")
        
        print("\n" + "="*80)
        print(f"End of scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)


def scan_file_directly(file_path, json_output=False):
    """Convenience function to scan a single file directly"""
    scanner = MalwareScanner(json_output=json_output)
    
    if os.path.exists(file_path):
        scanner.scan_path(file_path)
        scanner.print_results()
        return scanner.results
    else:
        print(f"{Fore.RED}Error: File '{file_path}' does not exist{Style.RESET_ALL}")
        return []


def simple_scan_file(file_path):
    """A simple function to scan a file for suspicious content that works without YARA"""
    print(f"Scanning file: {file_path}")
    
    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            print(f"{Fore.RED}Error: File {file_path} does not exist{Style.RESET_ALL}")
            return
        
        # Read the file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        file_size = len(content)
        print(f"File size: {file_size} bytes")
        
        # Basic suspicious patterns
        suspicious_patterns = [
            (b'powershell', "PowerShell command"),
            (b'cmd.exe', "Command prompt execution"),
            (b'http://', "HTTP URL"),
            (b'https://', "HTTPS URL"),
            (b'eval(', "JavaScript eval function"),
            (b'ActiveXObject', "ActiveX object creation"),
            (b'CreateObject', "COM object creation"),
            (b'Shell', "Shell command"),
            (b'WScript.Shell', "Windows Script Host"),
            (b'Auto_Open', "Auto-executing macro"),
            (b'Document_Open', "Document event macro"),
            (b'\x90\x90\x90\x90', "NOP sled (possible shellcode)"),
            (b'Equation.3', "Equation Editor (CVE-2017-11882)"),
            (b'objupdate', "Object update (RTF exploit)"),
            (b'objdata', "Object data (RTF exploit)")
        ]
        
        print("\nScanning for suspicious patterns...")
        found = False
        
        for pattern, description in suspicious_patterns:
            if pattern in content:
                print(f"{Fore.RED}[SUSPICIOUS] Found: {description}{Style.RESET_ALL}")
                found = True
        
        if not found:
            print(f"{Fore.GREEN}No suspicious patterns found{Style.RESET_ALL}")
        
        print("\nScan completed")
    
    except Exception as e:
        print(f"{Fore.RED}Error scanning file: {e}{Style.RESET_ALL}")


def colab_input_scanner():
    """Interactive scanner for Google Colab that takes file path as input"""
    print(f"{Fore.CYAN}Document Malware Scanner v1.0{Style.RESET_ALL}")
    print(f"Current Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Current User: {os.environ.get('USER', 'Unknown')}")
    print("\nThis scanner detects malicious content in document files.")
    
    while True:
        print("\nOptions:")
        print("1. Scan a single file")
        print("2. Scan a directory")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            file_path = input("\nEnter the full path of the file to scan: ").strip()
            if file_path:
                if os.path.isfile(file_path):
                    # Try to use YARA scanning first
                    try:
                        print(f"\nScanning {file_path}...\n")
                        scan_file_directly(file_path)
                    except Exception as e:
                        print(f"{Fore.RED}Error with full scan: {e}{Style.RESET_ALL}")
                        print("Trying simple scan instead...")
                        simple_scan_file(file_path)
                else:
                    print(f"{Fore.RED}Error: File does not exist or is not accessible{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No file path provided{Style.RESET_ALL}")
        
        elif choice == '2':
            dir_path = input("\nEnter the directory path to scan: ").strip()
            recursive = input("Scan recursively? (y/n): ").strip().lower() == 'y'
            
            if dir_path:
                if os.path.isdir(dir_path):
                    scanner = MalwareScanner(recursive=recursive)
                    print(f"\nScanning directory {dir_path}...")
                    scanner.scan_path(dir_path)
                    scanner.print_results()
                else:
                    print(f"{Fore.RED}Error: Directory does not exist or is not accessible{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No directory path provided{Style.RESET_ALL}")
        
        elif choice == '3':
            print("\nExiting scanner. Thank you for using Document Malware Scanner.")
            break
        
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")


# Main function for direct execution
if __name__ == "__main__":
    # Check if running in Colab
    in_colab = 'google.colab' in sys.modules
    
    if in_colab:
        # Use the interactive scanner for Colab
        try:
            print("Running in Google Colab environment")
            colab_input_scanner()
        except KeyboardInterrupt:
            print("\nScanner interrupted.")
        except Exception as e:
            print(f"\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
    else:
        # Simple command line version
        import argparse
        parser = argparse.ArgumentParser(description='Document Malware Scanner')
        parser.add_argument('target', nargs='?', default=None, help='File or directory to scan')
        parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories')
        parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
        
        args = parser.parse_args()
        
        if args.target:
            scan_file_directly(args.target, json_output=args.json)
        else:
            # No target provided, start interactive mode
            colab_input_scanner()