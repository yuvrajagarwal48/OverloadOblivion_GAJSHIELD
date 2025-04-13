"""
Malware Detection API
FastAPI application for malware detection of various file types
"""

import os
import json
import uvicorn
import logging
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, BackgroundTasks, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Import the pipeline functions
from scripts.pipeline import analyze_file, get_file_type

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("malware_detection_api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Malware Detection API",
    description="API for analyzing files for malicious content",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Setup templates directory
templates_path = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(templates_path, exist_ok=True)
templates = Jinja2Templates(directory=templates_path)

# Create a directory for temporary file storage
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Create a class for structured responses
class AnalysisResponse(BaseModel):
    file_name: str
    file_type: str
    analysis_timestamp: str
    is_malicious: bool
    risk_level: str
    score: float
    details: Optional[Dict[str, Any]] = None
    message: Optional[str] = None

# Background task to clean up uploaded files
def remove_file(file_path: str):
    """Remove a file after analysis is complete"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Removed temporary file: {file_path}")
    except Exception as e:
        logger.error(f"Error removing file {file_path}: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the home page with upload form"""
    # Simple HTML form for file upload
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Malware Detection Service</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            h1 {
                color: #2c3e50;
                text-align: center;
            }
            .upload-container {
                border: 2px dashed #ccc;
                padding: 20px;
                text-align: center;
                margin: 20px 0;
                border-radius: 5px;
            }
            #file-upload {
                display: none;
            }
            label {
                background-color: #3498db;
                color: white;
                padding: 10px 15px;
                border-radius: 4px;
                cursor: pointer;
                display: inline-block;
                margin-top: 10px;
            }
            #upload-btn {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px 15px;
                border-radius: 4px;
                cursor: pointer;
                margin-top: 15px;
            }
            #upload-btn:disabled {
                background-color: #95a5a6;
                cursor: not-allowed;
            }
            #result {
                margin-top: 20px;
                padding: 15px;
                border: 1px solid #ccc;
                border-radius: 5px;
                display: none;
            }
            .progress {
                display: none;
                margin-top: 15px;
                text-align: center;
            }
            .spinner {
                border: 4px solid rgba(0, 0, 0, 0.1);
                width: 36px;
                height: 36px;
                border-radius: 50%;
                border-left-color: #09f;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .status {
                color: #16a085;
                margin-top: 8px;
            }
            .error {
                color: #e74c3c;
            }
            .warning {
                color: #f39c12;
            }
            .success {
                color: #27ae60;
            }
            pre {
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <h1>Malware Detection Service</h1>
        <p>Upload a file to analyze it for potential malicious content.</p>
        <p><strong>Supported file types:</strong> PDF, Word documents (.doc, .docx), Excel files (.xls, .xlsx), Batch files (.bat), Executables (.exe)</p>
        
        <div class="upload-container">
            <h3>Select File to Analyze</h3>
            <p id="file-name">No file selected</p>
            <label for="file-upload">Choose File</label>
            <input type="file" id="file-upload" name="file">
            <br>
            <button id="upload-btn" disabled>Analyze File</button>
            
            <div class="progress">
                <div class="spinner"></div>
                <p class="status">Analyzing file...</p>
            </div>
        </div>
        
        <div id="result">
            <h3>Analysis Results</h3>
            <div id="result-content"></div>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const fileUpload = document.getElementById('file-upload');
                const fileName = document.getElementById('file-name');
                const uploadBtn = document.getElementById('upload-btn');
                const progress = document.querySelector('.progress');
                const result = document.getElementById('result');
                const resultContent = document.getElementById('result-content');
                
                fileUpload.addEventListener('change', function() {
                    if (fileUpload.files.length > 0) {
                        fileName.textContent = fileUpload.files[0].name;
                        uploadBtn.disabled = false;
                    } else {
                        fileName.textContent = 'No file selected';
                        uploadBtn.disabled = true;
                    }
                });
                
                uploadBtn.addEventListener('click', function() {
                    if (fileUpload.files.length === 0) return;
                    
                    const formData = new FormData();
                    formData.append('file', fileUpload.files[0]);
                    
                    // Show progress
                    progress.style.display = 'block';
                    uploadBtn.disabled = true;
                    
                    fetch('/analyze', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        // Hide progress
                        progress.style.display = 'none';
                        uploadBtn.disabled = false;
                        
                        // Display result
                        result.style.display = 'block';
                        
                        let resultHTML = '';
                        let riskClass = '';
                        
                        if (data.is_malicious) {
                            riskClass = 'error';
                        } else if (data.risk_level === 'medium') {
                            riskClass = 'warning';
                        } else {
                            riskClass = 'success';
                        }
                        
                        resultHTML += `<p><strong>File:</strong> ${data.file_name}</p>`;
                        resultHTML += `<p><strong>File Type:</strong> ${data.file_type}</p>`;
                        resultHTML += `<p><strong>Analysis Time:</strong> ${data.analysis_timestamp}</p>`;
                        resultHTML += `<p><strong>Risk Level:</strong> <span class="${riskClass}">${data.risk_level.toUpperCase()}</span></p>`;
                        resultHTML += `<p><strong>Malicious:</strong> ${data.is_malicious ? 'YES' : 'NO'}</p>`;
                        resultHTML += `<p><strong>Score:</strong> ${data.score}</p>`;
                        
                        if (data.message) {
                            resultHTML += `<p><strong>Message:</strong> ${data.message}</p>`;
                        }
                        
                        if (data.details) {
                            resultHTML += '<p><strong>Details:</strong></p>';
                            resultHTML += `<pre>${JSON.stringify(data.details, null, 2)}</pre>`;
                        }
                        
                        resultContent.innerHTML = resultHTML;
                    })
                    .catch(error => {
                        // Hide progress
                        progress.style.display = 'none';
                        uploadBtn.disabled = false;
                        
                        // Display error
                        result.style.display = 'block';
                        resultContent.innerHTML = `<p class="error">Error: ${error.message || 'Failed to analyze file'}</p>`;
                    });
                });
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_uploaded_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Analyze an uploaded file for malicious content
    
    Args:
        file: The file to analyze
        
    Returns:
        Analysis result
    """
    try:
        # Create a temporary file
        temp_file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Schedule file cleanup after analysis
        background_tasks.add_task(remove_file, temp_file_path)
        
        # Get file type
        file_type = get_file_type(temp_file_path)
        
        # If file type is not supported, return not malicious
        if file_type == 'unknown':
            logger.info(f"Unsupported file type for {file.filename}")
            return JSONResponse(content={
                "file_name": file.filename,
                "file_type": "unknown",
                "analysis_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "is_malicious": False,
                "risk_level": "unknown",
                "score": 0,
                "message": "Unsupported file type, no analysis performed"
            })
        
        # Analyze the file
        logger.info(f"Analyzing file: {file.filename} (Type: {file_type})")
        analysis_result = analyze_file(temp_file_path)
        
        # Extract summary information
        summary = analysis_result.get('summary', {})
        
        # Build response
        response = {
            "file_name": file.filename,
            "file_type": file_type,
            "analysis_timestamp": analysis_result.get('analysis_timestamp', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            "is_malicious": summary.get('is_malicious', False),
            "risk_level": summary.get('risk_level', 'unknown'),
            "score": summary.get('score', 0),
            "details": analysis_result
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing file {file.filename}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing file: {str(e)}")

@app.get("/health")
async def health_check():
    """API health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}

if __name__ == "__main__":
    # Run the FastAPI server
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)