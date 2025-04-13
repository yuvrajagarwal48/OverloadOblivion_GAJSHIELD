import os
import json
import logging
import tempfile
import speakeasy
from pefile import PEFormatError
from unicorn import UcError
from pathlib import Path
from numpy import sum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def write_error(errfile):
    # creating of empty file 
    Path(errfile).touch()

def emulate(file_path=None, report_folder=None, i=0, l=0, speakeasy_config=""):
    """
    Emulate an executable file and return the emulation results
    
    Args:
        file_path: Path to the executable file to analyze
        report_folder: Optional folder to save reports (if None, only returns data)
        i, l: Counters for batch processing (can be ignored for single file)
        speakeasy_config: Optional path to speakeasy config
        
    Returns:
        dict: Emulation results or None if emulation failed
    """
    # Use default sample file if none provided
    if file_path is None:
        # Look for .exe files in the current directory
        for file in os.listdir('.'):
            if file.endswith('.exe'):
                file_path = os.path.abspath(file)
                break
        
        if file_path is None:
            sample_path = os.path.join(os.path.dirname(__file__), '..', 'samples')
            if os.path.exists(sample_path):
                for file in os.listdir(sample_path):
                    if file.endswith('.exe'):
                        file_path = os.path.join(sample_path, file)
                        break
        
        if file_path is None:
            logger.error("No executable file found for analysis")
            return None
    
    # Create temporary directory for reports if none specified
    use_temp_dir = report_folder is None
    if use_temp_dir:
        report_folder = tempfile.mkdtemp()
    
    samplename = os.path.basename(file_path)
    reportfile = f"{report_folder}/{samplename}.json"
    errfile = f"{report_folder}/{samplename}.err"
    
    # Store results to return
    result_data = None
    
    # Skip if existing files found and a folder was specified
    if (not use_temp_dir) and os.path.exists(reportfile):
        logger.warning(f" [!] {i}/{l} Exists, skipping analysis: {reportfile}")
        # If output exists but we need to return data, load that file
        try:
            with open(reportfile, 'r') as f:
                result_data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading existing report: {str(e)}")
            result_data = None
    elif (not use_temp_dir) and os.path.exists(errfile):
        logger.warning(f" [!] {i}/{l} Error file exists, skipping analysis: {errfile}")
    else:
        try:
            config = json.load(open(speakeasy_config)) if speakeasy_config else None
            se = speakeasy.Speakeasy(config=config)
            module = se.load_module(file_path)
            se.run_module(module)
            report = se.get_report()

            took = report["emulation_total_runtime"]
            api_seq_len = sum([len(x["apis"]) for x in report["entry_points"]])
            
            if api_seq_len >= 1:
                # Store the results in result_data
                result_data = report["entry_points"]
                
                # Only save to file if report_folder was specified
                if not use_temp_dir:
                    with open(f"{reportfile}", "w") as f:
                        json.dump(result_data, f, indent=4)
        
            if api_seq_len == 1 or api_seq_len == 0:
                # some uninformative failures with 0 or 1 API calls - e.g. ordinal_100
                api = [x['apis'] for x in report['entry_points']][0] if api_seq_len == 1 else ''
                err = [x['error']['type'] if "error" in x.keys() and "type" in x["error"].keys() else "" for x in report['entry_points']]
                if "unsupported_api" in err:
                    try:
                        err.extend([x['error']['api']['name'] for x in report['entry_points']])
                    except KeyError:
                        err.extend([x['error']['api_name'] for x in report['entry_points']])
                logger.debug(f" [D] {i}/{l} API nr.: {api_seq_len}; Err: {err}; APIs: {api}")
                if api_seq_len == 0 and not use_temp_dir:
                    write_error(errfile)

            logger.info(f" [+] {i}/{l} Finished emulation {file_path}, took: {took:.2f}s, API calls acquired: {api_seq_len}")
            
            # Clean up temporary directory if we created one
            if use_temp_dir and os.path.exists(report_folder):
                import shutil
                shutil.rmtree(report_folder)

        except PEFormatError as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, PEFormatError: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
        except UcError as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, UcError: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
        except IndexError as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, IndexError: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
        except speakeasy.errors.NotSupportedError as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, NotSupportedError: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
        except speakeasy.errors.SpeakeasyError as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, SpeakEasyError: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
        except Exception as ex:
            logger.error(f" [-] {i}/{l} Failed emulation, general Exception: {file_path}\n{ex}\n")
            if not use_temp_dir:
                write_error(errfile)
            # Clean up temporary directory if we created one
            if use_temp_dir and os.path.exists(report_folder):
                import shutil
                shutil.rmtree(report_folder)

    return result_data

# Example usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = None
        
    results = emulate(filepath)
    if results:
        print(json.dumps(results, indent=2))
    else:
        print("Emulation failed or no results returned.")