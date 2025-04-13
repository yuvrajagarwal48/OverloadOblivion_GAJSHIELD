import os
import sys
import torch
import numpy as np
import argparse
from datetime import datetime

def print_header():
    print("\n" + "=" * 60)
    print("                 MalConv2 Malware Detector")
    print("=" * 60)
    print(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60 + "\n")

def read_bytes_from_file(file_path, max_length=2000000):
    """Read raw bytes from a file and pad/truncate to max_length"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    file_size = len(data)
    print(f"File size: {file_size:,} bytes")
    
    # Convert to numpy array
    data_np = np.frombuffer(data, dtype=np.uint8)
    
    # Pad or truncate
    if len(data_np) > max_length:
        print(f"File exceeds maximum length of {max_length:,} bytes. Truncating...")
        data_np = data_np[:max_length]
    else:
        print(f"Padding file to {max_length:,} bytes...")
        padding = np.zeros(max_length - len(data_np), dtype=np.uint8)
        data_np = np.concatenate([data_np, padding])
    
    return data_np, file_size

def load_model(model_path, device):
    """Load the MalConv2 model"""
    print(f"Loading model from {model_path}...")
    
    # First, make sure MalConv2 is in the path
    if not os.path.exists("MalConv2"):
        print("MalConv2 directory not found. Cloning repository...")
        os.system("git clone https://github.com/FutureComputing4AI/MalConv2.git")
    
    # Add to path if not already there
    if "MalConv2" not in sys.path:
        sys.path.append("MalConv2")
    
    # Try to import the model class
    try:
        from MalConv2.MalConvGCT_nocat import MalConvGCT
        print("Successfully imported MalConvGCT")
    except ImportError:
        try:
            sys.path.append(os.path.abspath("MalConv2"))
            from MalConv2.MalConvGCT_nocat import MalConvGCT
            print("Successfully imported MalConvGCT from absolute path")
        except ImportError:
            print("Failed to import MalConvGCT_nocat, trying MalConv...")
            try:
                from MalConv2.MalConv import MalConv as MalConvGCT
                print("Successfully imported MalConv as fallback")
            except ImportError:
                print("ERROR: Could not import either MalConvGCT_nocat or MalConv.")
                print("Please make sure the MalConv2 repository is properly cloned and accessible.")
                return None
    
    # Create model instance
    model = MalConvGCT(channels=256, window_size=256, stride=64)
    
    # Load model weights
    try:
        # Add safe globals for numpy's scalar type (needed for PyTorch 2.6+)
        import numpy as np
        import torch.serialization
        
        # Method 1: Try with safe globals context manager
        try:
            print("Attempting to load model with safe globals...")
            from torch.serialization import safe_globals
            with safe_globals(["numpy._core.multiarray.scalar"]):
                checkpoint = torch.load(model_path, map_location=device)
        except (ImportError, AttributeError):
            # Method 2: Try with add_safe_globals
            try:
                print("Safe globals context manager not available, trying with add_safe_globals...")
                torch.serialization.add_safe_globals(["numpy._core.multiarray.scalar"])
                checkpoint = torch.load(model_path, map_location=device)
            except (ImportError, AttributeError):
                # Method 3: Try with weights_only=False (less secure but may work)
                print("Safe globals not available, trying with weights_only=False...")
                checkpoint = torch.load(model_path, map_location=device, weights_only=False)
        
        # Extract state dict based on structure
        if isinstance(checkpoint, dict) and 'model_state_dict' in checkpoint:
            state_dict = checkpoint['model_state_dict']
        elif isinstance(checkpoint, dict) and 'state_dict' in checkpoint:
            state_dict = checkpoint['state_dict']
        else:
            state_dict = checkpoint
        
        # Remove 'module.' prefix if present
        if all(k.startswith('module.') for k in state_dict.keys()):
            state_dict = {k[7:]: v for k, v in state_dict.items()}
        
        # Load state dict into model
        model.load_state_dict(state_dict, strict=False)
        print("Model loaded successfully!")
        
        # Move model to device and set to evaluation mode
        model = model.to(device)
        model.eval()
        
        return model
    
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

def predict(model, file_path, device, max_length=2000000):
    """Predict if a file is malware using MalConv2"""
    try:
        # Read and process file
        data_np, file_size = read_bytes_from_file(file_path, max_length)
        
        # Convert to tensor
        data_tensor = torch.from_numpy(data_np).long().unsqueeze(0)  # Add batch dimension
        
        # Move to device
        data_tensor = data_tensor.to(device)
        
        print("Running inference...")
        # Get prediction
        with torch.no_grad():
            outputs = model(data_tensor)
            
            # Handle tuple output
            if isinstance(outputs, tuple):
                outputs = outputs[0]
            
            # Handle binary classification with 2 output units
            if len(outputs.shape) > 1 and outputs.shape[1] == 2:
                outputs = outputs[:, 1]
            
            # If we still have a tensor with multiple elements, take the first one
            if outputs.numel() > 1:
                outputs = outputs[0]
            
            # Get probability
            prob = torch.sigmoid(outputs).item()
        
        return prob
    
    except Exception as e:
        print(f"Error during prediction: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def display_result(file_path, prob):
    """Display the prediction result"""
    print("\n" + "-" * 60)
    print(f"ANALYSIS RESULT")
    print("-" * 60)
    print(f"File: {os.path.basename(file_path)}")
    
    if prob is None:
        print("Status: ERROR - Could not analyze file")
        return
    
    # Determine result
    is_malware = prob >= 0.5
    confidence = max(prob, 1-prob) * 100
    
    verdict = "MALWARE" if is_malware else "BENIGN"
    print(f"Verdict: {verdict}")
    print(f"Malware Probability: {prob:.4f} ({prob*100:.2f}%)")
    print(f"Confidence: {confidence:.2f}%")
    print("-" * 60)

def main(file_path=None, model_path=None, cpu=False):
    """Main function for standalone usage and module imports"""
    
    # Set defaults if not provided
    if not file_path:
        file_path = 'data\pip3.exe'  # Default file
    
    if not model_path:
        model_path = 'models\malconv2_finetuned.pt'  # Default model
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist.")
        return None
    
    # Check if model exists
    if not os.path.exists(model_path):
        print(f"Error: Model file {model_path} does not exist.")
        return None
    
    # Set device
    if cpu:
        device = torch.device('cpu')
    else:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load model
    model = load_model(model_path, device)
    if model is None:
        return None
    
    # Make prediction
    prob = predict(model, file_path, device)
    
    # Display result if called directly
    display_result(file_path, prob)
    
    # Return results for module usage
    result = {
        'file_path': file_path,
        'malware_probability': prob,
        'is_malicious': prob >= 0.5 if prob is not None else False,
        'confidence': max(prob, 1-prob) * 100 if prob is not None else 0,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return result

# if __name__ == "__main__":
#     main()