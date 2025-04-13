import json
import os
import sys
import logging
import datetime
import hashlib
from collections.abc import Iterable
from pandas import json_normalize
from google.generativeai import configure, GenerativeModel
import google.generativeai as genai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def flatten(l):
    """Flatten nested iterables into a single list"""
    for el in l:
        if isinstance(el, Iterable) and not isinstance(el, (str, bytes)):
            yield from flatten(el)
        else:
            yield el

def report_to_apiseq(report_data=None, reportfile_path=None):
    """
    Convert emulation report data to API sequence data for analysis
    
    Args:
        report_data (dict): Direct report data from emulation
        reportfile_path (str): Path to report file if report_data not provided
        
    Returns:
        dict: API sequence data or None if processing failed
    """
    # Handle report from file
    if reportfile_path is not None and report_data is None:
        try:
            filehash = os.path.basename(reportfile_path).strip(".json")
            with open(reportfile_path, 'r') as f:
                report_data = json.load(f)
        except json.decoder.JSONDecodeError as ex:
            logger.error(f"[-] {reportfile_path} JSONDecode exception: {ex}")
            return None
        except FileNotFoundError as ex:
            logger.error(f"[-] {reportfile_path} not found: {ex}")
            return None
    # Handle direct data input
    elif report_data is not None:
        # Generate a placeholder hash if using direct data
        if reportfile_path:
            filehash = os.path.basename(reportfile_path).strip(".json")
        else:
            import hashlib
            import time
            filehash = hashlib.md5(str(time.time()).encode()).hexdigest()
    else:
        logger.error("No valid report data provided")
        return None
        
    # Process the data
    try:
        report_fulldf = json_normalize(report_data)
        
        # Extract API sequence
        apiseq = list(flatten(report_fulldf["apis"].apply(lambda x: [y["api_name"].lower() for y in x]).values))
        
        # Create result object
        data = {
            "sha256": filehash, 
            "api.seq": apiseq, 
            "api.seq.len": len(apiseq)
        }
        
        return data
    except Exception as e:
        logger.error(f"Error processing report: {str(e)}")
        return None

def analyze_exe_with_gemini(api_call_data=None, api_call_report_path=None):
    """
    Send API call reports from dynamic analysis to Gemini 1.5 Flash to determine if it's malware.
    Can process either direct data or read from a file.
    
    Args:
        api_call_data (dict, optional): API call data as a dictionary
        api_call_report_path (str, optional): Path to the JSON file containing API call reports
    
    Returns:
        dict: Analysis result including malware verdict and explanation
    """
    try:
        # Handle different input methods
        if api_call_data is None and api_call_report_path is None:
            # Check for any JSON files in the current directory as a fallback
            json_files = [f for f in os.listdir('.') if f.endswith('.json')]
            if json_files:
                api_call_report_path = os.path.abspath(json_files[0])
                logger.info(f"Using default report file: {api_call_report_path}")
            else:
                # Try to get data from exe_dynamic_emulation
                try:
                    from exe_dynamic_emulation import emulate
                    api_call_data = emulate()
                    if api_call_data is None:
                        logger.error("No API call data available and no report files found")
                        return None
                except ImportError:
                    logger.error("No API call data available and no report files found")
                    return None
        
        # Load API call report from file if path is provided
        if api_call_data is None and api_call_report_path is not None:
            try:
                with open(api_call_report_path, 'r') as f:
                    api_call_data = json.load(f)
            except FileNotFoundError:
                logger.error(f"Error: File {api_call_report_path} not found")
                return None
            except json.JSONDecodeError:
                logger.error(f"Error: {api_call_report_path} is not a valid JSON file")
                return None
        
        # Check if API key is set
        api_key = os.environ.get("GEMINI_API_KEY", "AIzaSyA0XMComyoyZFdbZDL8aEnIDQPUNsCOGJ0")
        if not api_key:
            logger.error("Error: GEMINI_API_KEY environment variable not set")
            return None
        
        # Configure the Gemini API client
        configure(api_key=api_key)
        
        # Create a model instance
        model = GenerativeModel(model_name="gemini-1.5-flash")
        
        # Format API call data for better analysis
        api_calls_formatted = json.dumps(api_call_data, indent=2)
        
        # Craft a prompt for Gemini to analyze the file
        prompt = f"""
        You are a malware analyst examining API calls from dynamic analysis of an executable file.
        Given the following API call report from dynamic analysis, determine if this executable 
        is likely malicious or benign.

        Specifically look for:
        1. Suspicious API calls (process injection, registry modifications, network connections to unusual domains)

        API call report:
        {api_calls_formatted}
        
        Provide a detailed analysis explaining why you believe this is malware or not.
        Include a clear verdict (MALICIOUS or BENIGN) at the beginning of your response.If with caveats then return MALICIOUSx`
        """
        
        # Send the request to Gemini
        response = model.generate_content(prompt)
        
        # Extract and format the response
        analysis_text = response.text
        
        # Determine verdict from response
        if "MALICIOUS" in analysis_text.upper().split("\n")[0]:
            verdict = "MALICIOUS"
        elif "BENIGN" in analysis_text.upper().split("\n")[0]:
            verdict = "BENIGN"
        else:
            verdict = "UNCERTAIN"
        
        result = {
            "verdict": verdict,
            "analysis": analysis_text,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return result
    
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        return {"verdict": "ERROR", "analysis": f"Analysis failed: {str(e)}"}

# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        logger.info(f"Analyzing file: {report_path}")
        result = analyze_exe_with_gemini(api_call_report_path=report_path)
    else:
        # Try to get data from emulation
        try:
            from exe_dynamic_emulation import emulate
            api_data = emulate()
            if api_data:
                logger.info("Using data from emulation")
                result = analyze_exe_with_gemini(api_call_data=api_data)
            else:
                result = analyze_exe_with_gemini()  # Try to find a file
        except ImportError:
            result = analyze_exe_with_gemini()  # Try to find a file
    
    if result:
        print(f"\n{'='*50}")
        print(f"VERDICT: {result['verdict']}")
        print(f"{'='*50}\n")
        print("DETAILED ANALYSIS:")
        print(result['analysis'])
    else:
        print("Analysis failed")