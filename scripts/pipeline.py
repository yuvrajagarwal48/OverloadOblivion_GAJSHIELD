#!/usr/bin/env python3
"""
Pipeline Functions for Malware Detection
Provides standardized pipeline functions for different file types
"""

import os
import tempfile
import shutil
import hashlib
import logging
import glob
from datetime import datetime
from typing import Dict, Any, Union, Optional, List

# Import analyzers
from .pdf_static import PDFMalwareDetectorGemini as PDFMalwareDetector
from .bat_static import BatchFileAnalyzer
from .document_static import MalwareScanner
from .excel_static import MalwareDetector as ExcelMalwareDetector
from .exe_dynamic import analyze_exe_with_gemini, report_to_apiseq
from .exe_dynamic_emulation import emulate
from .exe_static1 import predict, load_model
from .apk_feature_extractor import extract_apk_features
from .apk_static import analyze_apk
from .qr_static import qr_analysis_pipeline
import torch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def get_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {str(e)}")
        return "hash_calculation_failed"

def find_sample_file(extension: str) -> Optional[str]:
    """
    Find a sample file with the specified extension
    
    Args:
        extension: File extension to look for (without dot)
        
    Returns:
        File path if found, None otherwise
    """
    # Look in current directory
    for file in os.listdir('.'):
        if file.lower().endswith(f'.{extension.lower()}'):
            return os.path.abspath(file)
    
    # Look in samples directory if it exists
    sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'samples')
    if os.path.exists(sample_path):
        for file in os.listdir(sample_path):
            if file.lower().endswith(f'.{extension.lower()}'):
                return os.path.join(sample_path, file)
    
    # Look in data directory if it exists
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    if os.path.exists(data_path):
        for file in os.listdir(data_path):
            if file.lower().endswith(f'.{extension.lower()}'):
                return os.path.join(data_path, file)
    
    return None

def pdf_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a PDF file for malicious content
    
    Args:
        file_path: Path to the PDF file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    # Find a sample file if none provided
    if file_path is None:
        file_path = find_sample_file('pdf')
        if file_path is None:
            logger.error("No PDF file found for analysis")
            return {
                'error': 'No PDF file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        logger.info(f"Using sample PDF file: {file_path}")
    
    try:
        logger.info(f"Starting PDF analysis for: {file_path}")
        
        # Create detector instance and analyze
        detector = PDFMalwareDetector()
        results = detector.analyze_pdf(file_path)
        
        # Add file hash
        if 'md5' not in results:
            results['file_hash'] = get_file_hash(file_path)
            
        # Add timestamp
        results['analysis_timestamp'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add summary for API response
        results['summary'] = {
            'file_path': file_path,
            'risk_level': results.get('risk_level', 'unknown'),
            'is_malicious': results.get('malicious', False),
            'score': results.get('score', 0),
        }
        
        return results
    except Exception as e:
        logger.error(f"Error in PDF analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def bat_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a batch file for malicious content
    
    Args:
        file_path: Path to the batch file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    try:
        # Use BatchFileAnalyzer's built-in sample finding if no file provided
        analyzer = BatchFileAnalyzer(file_path, verbose=False)
        report = analyzer.analyze()
        
        if not report:
            logger.error(f"No bat file found or analysis failed")
            return {
                'error': 'Analysis failed',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': file_path if file_path else 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        
        # Add summary for API response
        results = {
            'report': report,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': report['path'],
                'risk_level': report['risk_level'],
                'is_malicious': report['risk_level'] in ["MALICIOUS", "HIGH RISK"],
                'score': report['suspicious_score']
            }
        }
        
        return results
    except Exception as e:
        logger.error(f"Error in batch file analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path if file_path else 'none',
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path if file_path else 'none',
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def document_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a document file for malicious content
    
    Args:
        file_path: Path to the document file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    # Find a sample file if none provided
    if file_path is None:
        for ext in ['doc', 'docx', 'rtf', 'ppt', 'pptx']:
            file_path = find_sample_file(ext)
            if file_path:
                logger.info(f"Using sample document file: {file_path}")
                break
                
        if file_path is None:
            logger.error("No document file found for analysis")
            return {
                'error': 'No document file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
    
    try:
        logger.info(f"Starting document analysis for: {file_path}")
        
        # Use the document analyzer
        scanner = MalwareScanner()
        results = scanner.scan_file(file_path)
        
        if not results:
            results = []
        
        # Add file hash and timestamp
        file_hash = get_file_hash(file_path)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        # Process the results to identify if it's malicious
        is_malicious = False
        risk_level = "low"
        matches_count = 0
        
        if isinstance(results, list) and len(results) > 0:
            matches_count = sum(len(r.get('matches', [])) for r in results)
            is_malicious = matches_count > 0
            
            if matches_count > 5:
                risk_level = "high"
            elif matches_count > 0:
                risk_level = "medium"
        
        # Create summary
        processed_results = {
            'raw_results': results,
            'file_hash': file_hash,
            'analysis_timestamp': timestamp,
            'summary': {
                'file_path': file_path,
                'risk_level': risk_level,
                'is_malicious': is_malicious,
                'matches_found': matches_count
            }
        }
        
        return processed_results
    except Exception as e:
        logger.error(f"Error in document analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def excel_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze an Excel file for malicious content
    
    Args:
        file_path: Path to the Excel file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    # Find a sample file if none provided
    if file_path is None:
        for ext in ['xls', 'xlsx']:
            file_path = find_sample_file(ext)
            if file_path:
                logger.info(f"Using sample Excel file: {file_path}")
                break
                
        if file_path is None:
            logger.error("No Excel file found for analysis")
            return {
                'error': 'No Excel file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
    
    try:
        logger.info(f"Starting Excel file analysis for: {file_path}")
        
        # Create detector instance and analyze
        detector = ExcelMalwareDetector()
        result = detector.analyze_file(file_path)
        
        # Process results
        is_malicious = result['risk_level'] in ['Critical', 'High']
        
        # Create summary
        summary = {
            'file_path': file_path,
            'risk_level': result['risk_level'].lower(),
            'is_malicious': is_malicious,
            'score': result['risk_score']
        }
        
        # Add summary to result
        result['summary'] = summary
        result['analysis_timestamp'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        return result
    except Exception as e:
        logger.error(f"Error in Excel analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def exe_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze an executable file for malicious content
    
    Args:
        file_path: Path to the executable file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    # Find a sample file if none provided
    if file_path is None:
        file_path = find_sample_file('exe')
        if file_path is None:
            logger.error("No executable file found for analysis")
            return {
                'error': 'No executable file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        logger.info(f"Using sample executable file: {file_path}")
    
    try:
        logger.info(f"Starting executable analysis for: {file_path}")
        
        results = {}
        
        # Step 1: Static analysis using MalConv2 model from exe_static1.py
        try:
            logger.info("Performing static analysis with MalConv2...")
            
            # Set device
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            logger.info(f"Using device: {device}")
            
            # Load model
            model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'malconv2_finetuned.pt')
            model = load_model(model_path, device)
            
            if model is not None:
                # Make prediction
                prob = predict(model, file_path, device)
                
                # Add static analysis results
                results['static_analysis'] = {
                    'malware_probability': prob,
                    'is_malicious': prob >= 0.5 if prob is not None else False,
                    'confidence': max(prob, 1-prob) * 100 if prob is not None else 0
                }
            else:
                logger.warning("Failed to load MalConv2 model, skipping static analysis")
        except Exception as e:
            logger.error(f"Error in static analysis: {str(e)}")
            results['static_analysis'] = {
                'error': str(e)
            }
        
        # Step 2: Emulate the executable using speakeasy
        logger.info("Performing dynamic analysis with speakeasy emulator...")
        emulation_results = emulate(file_path)
        
        if not emulation_results:
            logger.warning(f"Emulation failed or no results generated for {file_path}")
            if 'static_analysis' not in results:
                return {
                    'error': 'Both static and dynamic analysis failed',
                    'file_path': file_path,
                    'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    'summary': {
                        'file_path': file_path,
                        'risk_level': 'unknown',
                        'is_malicious': False,
                        'score': 0
                    }
                }
        else:
            # Step 3: Parse the emulation results
            api_sequence = report_to_apiseq(report_data=emulation_results)
            results['api_sequence'] = api_sequence
            
            # Step 4: Analyze with Gemini using the data
            gemini_results = analyze_exe_with_gemini(api_call_data=emulation_results)
            results['gemini_analysis'] = gemini_results
        
        # Add metadata
        results['file_path'] = file_path
        results['analysis_timestamp'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        results['file_hash'] = get_file_hash(file_path)
        
        # Determine overall maliciousness from both analyses
        is_malicious = False
        risk_level = "low"
        score = 0
        
        # Check static analysis results
        if 'static_analysis' in results and results['static_analysis'].get('is_malicious', False):
            is_malicious = True
            risk_level = "high"
            score = max(score, results['static_analysis'].get('malware_probability', 0) * 100)
        
        # Check Gemini analysis results
        if 'gemini_analysis' in results and results['gemini_analysis'] and results['gemini_analysis'].get('verdict') == 'MALICIOUS':
            is_malicious = True
            risk_level = "high"
            score = max(score, 100)
        
        # Create summary
        results['summary'] = {
            'file_path': file_path,
            'risk_level': risk_level,
            'is_malicious': is_malicious,
            'score': score
        }
        
        return results
    except Exception as e:
        logger.error(f"Error in executable analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def apk_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze an APK file for malicious content
    
    Args:
        file_path: Path to the APK file, or None to find a sample
        
    Returns:
        Dictionary with analysis results
    """
    # Find a sample file if none provided
    if file_path is None:
        file_path = find_sample_file('apk')
        if file_path is None:
            logger.error("No APK file found for analysis")
            return {
                'error': 'No APK file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        logger.info(f"Using sample APK file: {file_path}")
    
    try:
        logger.info(f"Starting APK analysis for: {file_path}")
        
        # Step 1: Extract features from the APK
        temp_dir = tempfile.mkdtemp()
        try:
            features_file = os.path.join(temp_dir, os.path.basename(file_path).replace('.apk', '_features.csv'))
            logger.info(f"Extracting APK features to: {features_file}")
            
            # Extract features from the APK
            features, _ = extract_apk_features(file_path)
            
            # Convert to DataFrame and save as CSV
            import pandas as pd
            df = pd.DataFrame([features])
            df.to_csv(features_file, index=False)
            
            # Step 2: Analyze the extracted features
            results = analyze_apk(features_file)
            
            # Step 3: Add file metadata
            results['file_path'] = file_path
            results['file_hash'] = get_file_hash(file_path)
            
            return results
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        logger.error(f"Error in APK analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def zip_analysis_pipeline(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a ZIP archive by recursively extracting and analyzing each file inside
    
    Args:
        file_path: Path to the ZIP file, or None to find a sample
        
    Returns:
        Dictionary with analysis results for all contained files
    """
    # Find a sample file if none provided
    if file_path is None:
        file_path = find_sample_file('zip')
        if file_path is None:
            logger.error("No ZIP file found for analysis")
            return {
                'error': 'No ZIP file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        logger.info(f"Using sample ZIP file: {file_path}")
    
    try:
        logger.info(f"Starting ZIP archive analysis for: {file_path}")
        
        import zipfile
        
        # Check if it's a valid zip file
        if not zipfile.is_zipfile(file_path):
            return {
                'error': 'Not a valid ZIP file',
                'file_path': file_path,
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': file_path,
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
        
        # Create a temporary directory to extract files
        temp_dir = tempfile.mkdtemp()
        results = {
            'file_path': file_path,
            'file_hash': get_file_hash(file_path),
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'contents': [],
            'malicious_count': 0,
            'suspicious_count': 0,
            'clean_count': 0,
            'error_count': 0
        }
        
        try:
            # Extract all files from the ZIP
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # List files in the archive
                file_list = zip_ref.namelist()
                results['file_count'] = len(file_list)
                logger.info(f"Found {len(file_list)} files in ZIP archive")
                
                # Extract all files
                zip_ref.extractall(temp_dir)
                
                # Analyze each file
                for item in file_list:
                    extracted_path = os.path.join(temp_dir, item)
                    
                    # Skip directories
                    if os.path.isdir(extracted_path):
                        continue
                    
                    # Handle nested zip files recursively
                    if item.lower().endswith('.zip'):
                        logger.info(f"Found nested ZIP file: {item}")
                        nested_results = zip_analysis_pipeline(extracted_path)
                        results['contents'].append({
                            'relative_path': item,
                            'type': 'zip',
                            'analysis': nested_results
                        })
                        
                        # Update counts based on nested results
                        results['malicious_count'] += nested_results.get('malicious_count', 0)
                        results['suspicious_count'] += nested_results.get('suspicious_count', 0)
                        results['clean_count'] += nested_results.get('clean_count', 0)
                        results['error_count'] += nested_results.get('error_count', 0)
                    else:
                        # Analyze the individual file
                        logger.info(f"Analyzing extracted file: {item}")
                        file_type = get_file_type(extracted_path)
                        file_results = analyze_file(extracted_path)
                        
                        # Add to contents list
                        results['contents'].append({
                            'relative_path': item,
                            'type': file_type,
                            'analysis': file_results
                        })
                        
                        # Update counts based on results
                        if file_results.get('error'):
                            results['error_count'] += 1
                        elif file_results.get('summary', {}).get('is_malicious', False):
                            results['malicious_count'] += 1
                        elif file_results.get('summary', {}).get('risk_level') in ['medium', 'suspicious']:
                            results['suspicious_count'] += 1
                        else:
                            results['clean_count'] += 1
            
            # Calculate overall risk score
            malicious_weight = 1.0
            suspicious_weight = 0.5
            total_files = results['malicious_count'] + results['suspicious_count'] + results['clean_count']
            
            if total_files > 0:
                weighted_score = (results['malicious_count'] * malicious_weight + 
                                 results['suspicious_count'] * suspicious_weight) / total_files
                score = min(weighted_score * 100, 100)
            else:
                score = 0
            
            # Determine overall maliciousness
            is_malicious = results['malicious_count'] > 0
            if is_malicious:
                risk_level = "high" if results['malicious_count'] / max(total_files, 1) > 0.3 else "medium"
            elif results['suspicious_count'] > 0:
                risk_level = "medium" if results['suspicious_count'] / max(total_files, 1) > 0.3 else "low-medium"
            else:
                risk_level = "low"
                
            # Create summary
            results['summary'] = {
                'file_path': file_path,
                'risk_level': risk_level,
                'is_malicious': is_malicious,
                'score': score,
                'file_count': results['file_count'],
                'malicious_count': results['malicious_count'],
                'suspicious_count': results['suspicious_count'],
                'clean_count': results['clean_count'],
                'error_count': results['error_count']
            }
            
            return results
            
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        logger.error(f"Error in ZIP analysis: {str(e)}")
        return {
            'error': str(e),
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            }
        }

def get_file_type(file_path: str) -> str:
    """
    Determine the file type based on extension
    
    Args:
        file_path: Path to the file
        
    Returns:
        File type string ('pdf', 'doc', 'xls', 'exe', 'bat', 'apk', 'qr', or 'unknown')
    """
    extension = os.path.splitext(file_path)[1].lower()
    
    # Map extensions to file types
    extension_map = {
        '.pdf': 'pdf',
        '.doc': 'doc', 
        '.docx': 'doc',
        '.xls': 'xls', 
        '.xlsx': 'xls',
        '.csv': 'xls',
        '.exe': 'exe',
        '.bat': 'bat',
        '.rtf': 'doc',
        '.ppt': 'doc',
        '.pptx': 'doc',
        '.apk': 'apk',
        '.qr': 'qr',
        '.png': 'qr',
        '.jpg': 'qr',
        '.jpeg': 'qr',
        '.zip': 'zip'
    }
    
    return extension_map.get(extension, 'unknown')

def analyze_file(file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a file by determining its type and routing to the appropriate pipeline
    
    Args:
        file_path: Path to the file to analyze, or None to find a suitable sample
        
    Returns:
        Dictionary with analysis results
    """
    # If no file provided, try to find any analyzable file
    if file_path is None:
        for ext in ['exe', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'bat', 'apk', 'qr']:  # Add QR support
            file_path = find_sample_file(ext)
            if file_path:
                logger.info(f"Using sample file for analysis: {file_path}")
                break
                
        if file_path is None:
            logger.error("No suitable file found for analysis")
            return {
                'error': 'No suitable file found for analysis',
                'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                'summary': {
                    'file_path': 'none',
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                }
            }
    
    file_type = get_file_type(file_path)
    logger.info(f"Analyzing file: {file_path} (detected type: {file_type})")
    
    # Route to appropriate pipeline based on file type
    if file_type == 'pdf':
        return pdf_analysis_pipeline(file_path)
    elif file_type == 'doc':
        return document_analysis_pipeline(file_path)
    elif file_type == 'xls':
        return excel_analysis_pipeline(file_path)
    elif file_type == 'exe':
        return exe_analysis_pipeline(file_path)
    elif file_type == 'bat':
        return bat_analysis_pipeline(file_path)
    elif file_type == 'apk':  # Add APK support
        return apk_analysis_pipeline(file_path)
    elif file_type == 'qr':  # Add QR support
        return qr_analysis_pipeline(file_path)
    elif file_type == 'zip':  # Add ZIP support
        return zip_analysis_pipeline(file_path)
    else:
        # Unknown file type
        return {
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'file_path': file_path,
                'risk_level': 'unknown',
                'is_malicious': False,
                'score': 0,
                'message': 'Unsupported file type'
            }
        }

# Simple test function for debugging
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if os.path.exists(file_path):
            results = analyze_file(file_path)
            print(json.dumps(results, indent=2))
        else:
            print(f"File not found: {file_path}")
    else:
        # Run with no arguments to demonstrate auto-detection
        print("No file path provided, attempting to find and analyze a sample file...")
        results = analyze_file()
        print(json.dumps(results, indent=2))