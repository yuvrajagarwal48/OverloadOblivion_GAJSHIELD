#!/usr/bin/env python3
import os
import re
import json
import subprocess
import hashlib
import tempfile
import argparse
import logging
import yara
from datetime import datetime
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Configure logging to match the project-wide format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class PDFMalwareDetectorGemini:
    """PDF Malware Detector using custom YARA rules, peepdf and Gemini AI"""
    
    def __init__(self, yara_rules_path=None, gemini_api_key=None):
        """Initialize the detector with YARA rules and Gemini API"""
        # Use default rules path relative to the script location if none provided
        if yara_rules_path is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_rules = os.path.join(script_dir, '..', 'rules', 'pdf_rules.yara')
            if os.path.exists(default_rules):
                yara_rules_path = default_rules
            else:
                yara_rules_path = "custom_pdf_rules.yara"  # Fallback
        
        try:
            # Load YARA rules
            if os.path.exists(yara_rules_path):
                self.yara_rules = yara.compile(filepath=yara_rules_path)
                logger.info(f"YARA rules loaded from {yara_rules_path}")
            else:
                logger.error(f"Error: YARA rules file not found at {yara_rules_path}")
                self.yara_rules = None
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.yara_rules = None
        
        # Configure Gemini API
        self.gemini_configured = False
        if gemini_api_key is None:
            # Try to get from environment
            gemini_api_key = os.environ.get("GEMINI_API_KEY", "AIzaSyA0XMComyoyZFdbZDL8aEnIDQPUNsCOGJ0")
            
        if gemini_api_key:
            try:
                genai.configure(api_key=gemini_api_key)
                self.model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    safety_settings={
                        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE
                    }
                )
                self.gemini_configured = True
                logger.info("Gemini API configured successfully")
            except Exception as e:
                logger.error(f"Error configuring Gemini API: {e}")
        
        # Log initialization
        current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"PDF analyzer initialized at (UTC): {current_time}")
        logger.info(f"Current user: {os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))}")

    def _run_command(self, cmd, timeout=60):
        """Run a command and return the output"""
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
            return output.decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            return e.output.decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return f"Command not found: {cmd[0]}"
        except Exception as e:
            return f"Error running command {cmd}: {str(e)}"
    
    def analyze_with_yara(self, pdf_path):
        """Analyze PDF using YARA rules"""
        if not hasattr(self, 'yara_rules') or self.yara_rules is None:
            return {'error': "YARA rules not compiled"}
        
        try:
            # Match YARA rules against the PDF
            matches = self.yara_rules.match(pdf_path)
            
            # Extract match information with scores
            score = 0
            match_details = []
            
            for match in matches:
                rule_name = match.rule
                weight = match.meta.get('weight', 1)  # Default weight if not specified
                description = match.meta.get('description', '')
                
                match_details.append({
                    'rule': rule_name,
                    'weight': weight,
                    'description': description,
                    'meta': match.meta,
                    'strings': [(s.identifier, s.instances) for s in match.strings]
                })
                
                score += weight
            
            # Prepare results dictionary
            results = {
                'matches': [match.rule for match in matches],
                'match_details': match_details,
                'score': score,
                'match_count': len(matches)
            }
            
            return results
            
        except Exception as e:
            print(f"Error in YARA analysis: {e}")
            return {'error': str(e)}
    
    def analyze_with_peepdf(self, pdf_path):
        """Analyze PDF using peepdf with advanced options"""
        try:
            # Run peepdf with interactive mode to get JSON output
            temp_script = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
            
            # Create script with commands for peepdf interactive mode
            commands = [
                "info",
                "metadata",
                "object 1",      # Usually the catalog
                "search /JS",
                "search /JavaScript",
                "search /OpenAction",
                "search /Launch",
                "search /AA",
                "search /URI",
                "search /RichMedia",
                "search /JBIG2Decode",
                "search /ObjStm",
                "search /XFA",
                "search /EmbeddedFile",
                "js_code",
                "quit"
            ]
            
            temp_script.write("\n".join(commands))
            temp_script.close()
            
            # Run peepdf with the script
            cmd = ["peepdf", "-f", "-s", temp_script.name, pdf_path]
            output = self._run_command(cmd, timeout=120)
            
            # Clean up temp file
            os.unlink(temp_script.name)
            
            if not output:
                return {'error': 'Failed to run peepdf command or no output'}
            
            # Parse peepdf output
            results = self._parse_peepdf_output(output)
            
            return results
            
        except Exception as e:
            print(f"Error in peepdf analysis: {e}")
            return {'error': str(e)}
    
    def _parse_peepdf_output(self, output):
        """Parse peepdf output into structured data"""
        results = {
            'js_found': "JavaScript code found" in output,
            'suspicious_elements': [],
            'urls': [],
            'raw_output': output,
            'catalog': {},
            'document_structure': {}
        }
        
        # Extract PDF version
        version_match = re.search(r'PDF Version:\s+(.+)', output)
        if version_match:
            results['version'] = version_match.group(1)
        
        # Extract binary analysis
        binary_match = re.search(r'Binary Analysis:\s+(.+)', output)
        if binary_match and "suspicious" in binary_match.group(1).lower():
            results['suspicious_elements'].append("Suspicious binary structure")
        
        # Extract suspicious elements
        if "suspicious elements" in output.lower():
            results['suspicious_elements'].append("Marked as suspicious by peepdf")
        
        # Extract embedded files
        if re.search(r'/EmbeddedFile', output, re.IGNORECASE):
            results['suspicious_elements'].append("Embedded files")
        
        # Extract encryption
        if "Encrypted" in output:
            results['suspicious_elements'].append("Encrypted content")
        
        # Extract stream filters
        filters = re.findall(r'/Filter\s*(/\w+)', output)
        if filters:
            results['filters'] = filters
            if "/ASCIIHexDecode" in filters or "/ASCII85Decode" in filters:
                results['suspicious_elements'].append("Uses ASCII encoding filters")
            if "/JBIG2Decode" in filters:
                results['suspicious_elements'].append("Uses JBIG2 compression")
        
        # Extract object structure
        obj_count_match = re.search(r'Objects\s*\((\d+)\)', output)
        stream_count_match = re.search(r'Streams\s*\((\d+)\)', output)
        
        if obj_count_match:
            results['object_count'] = int(obj_count_match.group(1))
        if stream_count_match:
            results['stream_count'] = int(stream_count_match.group(1))
            
        # Extract URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', output)
        if urls:
            results['urls'] = urls
            if len(urls) > 5:
                results['suspicious_elements'].append(f"Multiple URLs found ({len(urls)})")
        
        # Extract JavaScript code
        js_code_section = re.search(r'JavaScript code extracted:\s+(.+?)(?=\n\s*\n|\n\[)', output, re.DOTALL)
        if js_code_section:
            js_code = js_code_section.group(1).strip()
            results['javascript_code'] = js_code
            
            # Look for suspicious JS patterns
            js_suspicious_patterns = [
                (r'eval\s*\(', "eval()"),
                (r'unescape\s*\(', "unescape()"),
                (r'String\.fromCharCode', "String.fromCharCode()"),
                (r'getAnnots\s*\(', "getAnnots()"),
                (r'getIcon\s*\(', "getIcon()"),
                (r'util\.printf', "util.printf()"),
                (r'Collab\.collectEmailInfo', "Collab.collectEmailInfo()"),
                (r'app\.alert', "app.alert()"),
                (r'app\.execMenuItem', "app.execMenuItem()"),
                (r'app\.launchURL', "app.launchURL()"),
                (r'(\w+)\s*=\s*\w+\.split\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', "String splitting")
            ]
            
            for pattern, name in js_suspicious_patterns:
                if re.search(pattern, js_code, re.IGNORECASE):
                    results['suspicious_elements'].append(f"JavaScript: {name}")
                    
            # Check for obfuscation indicators
            obfuscation_indicators = [
                (r'(\\x[0-9a-fA-F]{2}){10,}', "Hex-encoded strings"),
                (r'(%u[0-9a-fA-F]{4}){10,}', "Unicode-encoded strings"),
                (r'(["\']\s*\+\s*["\']){5,}', "Excessive string concatenation"),
                (r'String\.fromCharCode\(\d+(?:\s*,\s*\d+){20,}\)', "Long fromCharCode sequence")
            ]
            
            for pattern, name in obfuscation_indicators:
                if re.search(pattern, js_code, re.IGNORECASE):
                    results['suspicious_elements'].append(f"JS Obfuscation: {name}")
        
        # Calculate basic score
        score = 0
        
        # Score for JavaScript presence
        if results['js_found']:
            score += 1
            
            # If peepdf specifically marks it as suspicious, give additional weight
            if "suspicious elements" in output.lower() and "JavaScript" in output:
                score += 1
        
        # Score for embedded files
        if "Embedded files" in results['suspicious_elements']:
            score += 1
        
        # Score for encryption with other suspicious elements
        if "Encrypted content" in results['suspicious_elements'] and len(results['suspicious_elements']) > 1:
            score += 0.5
            
        # Score for suspicious binary structure
        if "Suspicious binary structure" in results['suspicious_elements']:
            score += 1.5
        
        # Score for JS obfuscation indicators
        for element in results['suspicious_elements']:
            if "JS Obfuscation:" in element or "JavaScript:" in element:
                score += 0.5
        
        # Add our calculated score
        results['score'] = score
        
        return results
    
    def analyze_with_gemini(self, pdf_info, yara_results, peepdf_results):
        """Use Gemini to analyze PDF maliciousness based on gathered data"""
        if not self.gemini_configured:
            return {'error': "Gemini API not configured"}
            
        try:
            # Construct a detailed prompt for Gemini
            prompt = """
You are an expert PDF malware analyst. I need you to analyze a PDF file for malicious content. Please determine if this PDF is likely malicious or benign based on the provided analysis data, and explain your reasoning in detail.

## PDF File Information
- File: {file_path}
- Size: {file_size} bytes
- MD5: {md5}
- SHA256: {sha256}

## YARA Analysis Results
{yara_results}

## peepdf Analysis Results
{peepdf_results}

Based on this information, classify this PDF as either:
1. MALICIOUS: The PDF is highly likely to contain malicious code
2. SUSPICIOUS: The PDF contains suspicious elements but may not be definitively malicious
3. BENIGN: The PDF is likely safe

Also provide:
- A confidence level (percentage: e.g., "Confidence: 85%")
- The specific indicators that informed your decision
- What this PDF might be attempting to do if malicious
- Any additional security recommendations

IMPORTANT: Begin your response with your classification (MALICIOUS, SUSPICIOUS, or BENIGN) in capital letters.
""".format(
                file_path=pdf_info.get('file_path', 'Unknown'),
                file_size=pdf_info.get('file_size', 0),
                md5=pdf_info.get('md5', 'Unknown'),
                sha256=pdf_info.get('sha256', 'Unknown'),
                yara_results=self._format_yara_for_gemini(yara_results),
                peepdf_results=self._format_peepdf_for_gemini(peepdf_results)
            )
            
            # Send to Gemini AI for analysis
            response = self.model.generate_content(prompt)
            
            # Extract the classification decision
            classification_match = re.search(r'(MALICIOUS|SUSPICIOUS|BENIGN)', response.text, re.IGNORECASE)
            classification = "UNKNOWN"
            if classification_match:
                classification = classification_match.group(1).upper()
                
            # Prepare results
            gemini_results = {
                'classification': classification,
                'explanation': response.text,
                'is_malicious': classification == "MALICIOUS",
                'is_suspicious': classification == "SUSPICIOUS",
                'confidence': self._extract_confidence_from_response(response.text),
                'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            }
            
            return gemini_results
            
        except Exception as e:
            logger.error(f"Error in Gemini analysis: {e}")
            return {'error': str(e)}
    
    def _format_yara_for_gemini(self, yara_results):
        """Format YARA results for Gemini in a clear, detailed format"""
        if isinstance(yara_results, dict) and 'error' in yara_results:
            return f"YARA analysis failed: {yara_results['error']}"
            
        if not yara_results.get('matches', []):
            return "No YARA rules matched."
            
        formatted = "YARA matched rules:\n"
        for detail in yara_results.get('match_details', []):
            formatted += f"- Rule: {detail['rule']} (Weight: {detail['weight']})\n"
            formatted += f"  Description: {detail.get('description', 'No description')}\n"
            
            # Add string matches if available
            if 'strings' in detail and detail['strings']:
                formatted += "  Matched on:\n"
                for identifier, instances in detail['strings']:
                    if instances:
                        formatted += f"    - {identifier} at offsets: {', '.join(str(i[0]) for i in instances[:3])}"
                        if len(instances) > 3:
                            formatted += f" (+{len(instances)-3} more)"
                        formatted += "\n"
                        
            formatted += "\n"
            
        formatted += f"Total YARA score: {yara_results.get('score', 0)}\n"
        return formatted
    
    def _format_peepdf_for_gemini(self, peepdf_results):
        """Format peepdf results for Gemini in a clear, detailed format"""
        if isinstance(peepdf_results, dict) and 'error' in peepdf_results:
            return f"peepdf analysis failed: {peepdf_results['error']}"
            
        formatted = "peepdf analysis:\n"
        formatted += f"- PDF Version: {peepdf_results.get('version', 'Unknown')}\n"
        formatted += f"- Object Count: {peepdf_results.get('object_count', 'Unknown')}\n"
        formatted += f"- Stream Count: {peepdf_results.get('stream_count', 'Unknown')}\n"
        
        # Add suspicious elements
        if peepdf_results.get('suspicious_elements', []):
            formatted += "- Suspicious Elements:\n"
            for element in peepdf_results['suspicious_elements']:
                formatted += f"  - {element}\n"
        else:
            formatted += "- No suspicious elements detected\n"
            
        # Add JavaScript information
        if peepdf_results.get('js_found', False):
            formatted += "- JavaScript code found in the PDF\n"
            
            # Include a snippet of the JS code if available (truncated for Gemini)
            js_code = peepdf_results.get('javascript_code', '')
            if js_code:
                # Truncate long JavaScript to a manageable size
                if len(js_code) > 1000:
                    js_snippet = js_code[:1000] + "... [truncated]"
                else:
                    js_snippet = js_code
                    
                formatted += "- JavaScript snippet:\n```javascript\n"
                formatted += js_snippet
                formatted += "\n```\n"
        else:
            formatted += "- No JavaScript code found\n"
            
        # Add URL information
        if peepdf_results.get('urls', []):
            formatted += "- URLs found:\n"
            for url in peepdf_results['urls'][:10]:  # Limit to first 10 URLs
                formatted += f"  - {url}\n"
            
            if len(peepdf_results['urls']) > 10:
                formatted += f"  - (+ {len(peepdf_results['urls']) - 10} more URLs)\n"
        else:
            formatted += "- No URLs found\n"
            
        # Add filters information
        if peepdf_results.get('filters', []):
            formatted += "- Filters used:\n"
            for filter_name in peepdf_results['filters']:
                formatted += f"  - {filter_name}\n"
                
        formatted += f"- peepdf suspicion score: {peepdf_results.get('score', 0)}\n"
        
        return formatted
    
    def _extract_confidence_from_response(self, response_text):
        """Extract confidence level from Gemini response if present"""
        confidence_match = re.search(r'confidence:?\s*(\d+)%', response_text, re.IGNORECASE)
        if confidence_match:
            return int(confidence_match.group(1))
        
        # Look for strong confidence indicators
        if re.search(r'(high confidence|very likely|clearly|definitely|without doubt)', response_text, re.IGNORECASE):
            return 90
        elif re.search(r'(moderate confidence|likely|probably|seems to be)', response_text, re.IGNORECASE):
            return 70
        elif re.search(r'(low confidence|possibly|might be|could be|uncertain)', response_text, re.IGNORECASE):
            return 50
        
        # Default confidence
        return 75
    
    def analyze_pdf(self, pdf_path):
        """Analyze PDF using all methods and return combined results"""
        if not os.path.isfile(pdf_path):
            logger.error(f"File not found: {pdf_path}")
            return {'error': f"File not found: {pdf_path}"}
        
        # Basic file info
        file_size = os.path.getsize(pdf_path)
        
        try:
            with open(pdf_path, 'rb') as f:
                data = f.read(10)  # Just read a few bytes to check header
                if not data.startswith(b'%PDF-'):
                    logger.error(f"Not a valid PDF file: {pdf_path}")
                    return {'error': 'Not a PDF file', 'file_path': pdf_path, 'file_size': file_size}
        except Exception as e:
            logger.error(f"Error reading file {pdf_path}: {e}")
            return {'error': f"Error reading file: {e}", 'file_path': pdf_path, 'file_size': file_size}
        
        # Calculate file hashes
        with open(pdf_path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        
        # Initialize results
        pdf_info = {
            'file_path': pdf_path,
            'file_size': file_size,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256
        }
        
        # Run YARA analysis
        logger.info(f"Running YARA analysis on {pdf_path}")
        yara_results = self.analyze_with_yara(pdf_path)
        if 'error' in yara_results:
            logger.warning(f"YARA analysis failed: {yara_results['error']}")
        
        # Run peepdf analysis
        logger.info(f"Running peepdf analysis on {pdf_path}")
        peepdf_results = self.analyze_with_peepdf(pdf_path)
        if 'error' in peepdf_results:
            logger.warning(f"peepdf analysis failed: {peepdf_results['error']}")
        
        # Combine results before sending to Gemini
        combined_score = (
            yara_results.get('score', 0) +
            peepdf_results.get('score', 0)
        )
        
        # Calculate preliminary risk level with more granular scoring
        if combined_score >= 10:
            risk_level = "critical"
            likely_malicious = True
        elif combined_score >= 8:
            risk_level = "high"
            likely_malicious = True
        elif combined_score >= 5:
            risk_level = "medium"
            likely_malicious = False
        elif combined_score >= 3:
            risk_level = "low-medium"
            likely_malicious = False
        else:
            risk_level = "low"
            likely_malicious = False
        
        # Run Gemini analysis if configured
        gemini_results = None
        if self.gemini_configured:
            logger.info("Running Gemini AI analysis...")
            gemini_results = self.analyze_with_gemini(pdf_info, yara_results, peepdf_results)
            if 'error' in gemini_results:
                logger.error(f"Gemini AI analysis failed: {gemini_results['error']}")
            else:
                # Override with Gemini's decision if available and confidence is high enough
                confidence = gemini_results.get('confidence', 0)
                
                if gemini_results.get('is_malicious', False) and confidence >= 70:
                    likely_malicious = True
                    risk_level = "critical" if confidence >= 90 else "high"
                elif gemini_results.get('is_suspicious', False):
                    if confidence >= 80:
                        likely_malicious = True
                        risk_level = "high"
                    else:
                        likely_malicious = likely_malicious or (confidence > 75)
                        risk_level = "medium"
                elif confidence >= 85 and gemini_results.get('classification', '') == "BENIGN":
                    # Only downgrade if we're very confident it's benign
                    if risk_level not in ["high", "critical"]:
                        risk_level = "low"
                        likely_malicious = False
        
        # Calculate score based on the risk level for consistent reporting across all file types
        score = 0
        if risk_level == "critical":
            score = 90 + min(combined_score, 10)  # 90-100
        elif risk_level == "high":
            score = 70 + min(combined_score, 20)  # 70-90
        elif risk_level == "medium":
            score = 40 + min(combined_score * 2, 30)  # 40-70
        elif risk_level == "low-medium":
            score = 20 + min(combined_score * 3, 20)  # 20-40
        else:  # low
            score = min(combined_score * 4, 20)  # 0-20
        
        # Final combined results
        results = {
            **pdf_info,
            'yara': yara_results,
            'peepdf': peepdf_results,
            'gemini': gemini_results,
            'combined_score': combined_score,
            'risk_level': risk_level,
            'malicious': likely_malicious,
            'score': score,  # Standardized score for consistency with other analyzers
            'suspicious_count': (
                len(yara_results.get('matches', [])) +
                len(peepdf_results.get('suspicious_elements', []))
            ),
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        logger.info(f"PDF analysis complete: {os.path.basename(pdf_path)} - Risk: {risk_level} - Score: {score}")
        return results

    def generate_report(self, results):
        """Generate a comprehensive analysis report"""
        if 'error' in results:
            return f"Error: {results['error']}"
            
        report = "=== PDF Malware Analysis Report ===\n\n"
        report += f"File: {results['file_path']}\n"
        report += f"Size: {results['file_size']:,} bytes\n"
        report += f"MD5: {results['md5']}\n"
        report += f"SHA1: {results['sha1']}\n"
        report += f"SHA256: {results['sha256']}\n"
        report += f"Analysis Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
        
        # Risk assessment summary
        report += "=== RISK ASSESSMENT ===\n"
        report += f"RISK LEVEL: {results['risk_level'].upper()}\n"
        
        if results.get('malicious', False):
            report += "VERDICT: LIKELY MALICIOUS\n"
        elif results.get('risk_level') == "medium":
            report += "VERDICT: SUSPICIOUS (potentially unwanted elements)\n"
        else:
            report += "VERDICT: LIKELY BENIGN\n"
            
        report += f"Combined Score: {results.get('combined_score', 0):.1f}\n"
        report += f"Suspicious Element Count: {results.get('suspicious_count', 0)}\n\n"
        
        # YARA analysis
        report += "=== YARA ANALYSIS ===\n"
        yara_results = results.get('yara', {})
        if 'error' in yara_results:
            report += f"YARA analysis failed: {yara_results['error']}\n"
        elif not yara_results.get('matches', []):
            report += "No YARA rules matched.\n"
        else:
            report += f"Matched {len(yara_results.get('matches', []))} YARA rules:\n"
            for detail in yara_results.get('match_details', []):
                report += f"- Rule: {detail['rule']} (Weight: {detail['weight']})\n"
                report += f"  Description: {detail.get('description', 'No description')}\n"
            report += f"YARA Score: {yara_results.get('score', 0)}\n"
        report += "\n"
        
        # peepdf analysis
        report += "=== peepdf ANALYSIS ===\n"
        peepdf_results = results.get('peepdf', {})
        if 'error' in peepdf_results:
            report += f"peepdf analysis failed: {peepdf_results['error']}\n"
        else:
            report += f"PDF Version: {peepdf_results.get('version', 'Unknown')}\n"
            report += f"Objects: {peepdf_results.get('object_count', 'Unknown')}\n"
            report += f"Streams: {peepdf_results.get('stream_count', 'Unknown')}\n"
            
            # JavaScript status
            if peepdf_results.get('js_found', False):
                report += "JavaScript: Present\n"
            else:
                report += "JavaScript: Not found\n"
                
            # Suspicious elements
            if peepdf_results.get('suspicious_elements', []):
                report += "\nSuspicious Elements:\n"
                for element in peepdf_results['suspicious_elements']:
                    report += f"- {element}\n"
            
            # URLs
            if peepdf_results.get('urls', []):
                report += "\nURLs found:\n"
                for url in peepdf_results['urls'][:5]:  # Show only first 5 URLs
                    report += f"- {url}\n"
                if len(peepdf_results['urls']) > 5:
                    report += f"- (+ {len(peepdf_results['urls']) - 5} more URLs)\n"
            
            report += f"\npeepdf Score: {peepdf_results.get('score', 0)}\n"
        report += "\n"
        
        # Gemini analysis
        if results.get('gemini'):
            gemini_results = results['gemini']
            report += "=== GEMINI AI ANALYSIS ===\n"
            if 'error' in gemini_results:
                report += f"Gemini analysis failed: {gemini_results['error']}\n"
            else:
                report += f"Classification: {gemini_results.get('classification', 'UNKNOWN')}\n"
                report += f"Confidence: {gemini_results.get('confidence', 0)}%\n\n"
                report += "AI Analysis:\n"
                report += gemini_results.get('explanation', 'No explanation provided.')
        report += "\n"
        
        return report

# def main():
#     """Main function for the PDF Malware Detector script"""
#     print("=== PDF Malware Detector with Gemini AI ===")
    
#     # Make sure a default return value is established
#     results = None
    
#     try:
#         # Get arguments from command line if provided, otherwise use defaults
#         import argparse
#         parser = argparse.ArgumentParser(description='PDF Malware Detector')
#         parser.add_argument('--pdf', dest='pdf_path', help='Path to PDF file')
#         parser.add_argument('--yara', dest='yara_rules', default='rules/pdf_rules.yara', help='Path to YARA rules file')
#         parser.add_argument('--api-key', dest='api_key', default="AIzaSyA0XMComyoyZFdbZDL8aEnIDQPUNsCOGJ0", 
#                             help='Gemini API key')
#         parser.add_argument('--output', dest='output', help='Output file for report')
        
#         args = parser.parse_args()
        
#         pdf_path = args.pdf_path
#         yara_rules_path = args.yara_rules
#         api_key = args.api_key
#         output = args.output
        
#         # Create detector and analyze
#         detector = PDFMalwareDetectorGemini(yara_rules_path, api_key)
        
#         if pdf_path:
#             results = detector.analyze_pdf(pdf_path)
            
#             # Generate report
#             report = detector.generate_report(results)
            
#             # Output report
#             if output:
#                 with open(output, 'w') as f:
#                     f.write(report)
#                 print(f"Report saved to {output}")
#             else:
#                 print("\n" + report)
#     except Exception as e:
#         print(f"Error in main: {str(e)}")
#         import traceback
#         traceback.print_exc()
    
#     # Return results for module usage
#     return results

# if __name__ == "__main__":
#     main()