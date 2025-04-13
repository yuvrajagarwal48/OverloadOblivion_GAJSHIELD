from androguard.misc import AnalyzeAPK
import sys
import os
import pandas as pd

def load_malware_dataset(csv_path):
    """Load the malware/benign dataset from CSV file"""
    try:
        df = pd.read_csv(csv_path)
        # Get all permission columns from the CSV
        permission_columns = [col for col in df.columns if col != 'package_name' and col != 'label']
        # Create mapping of package names to labels
        return df.set_index('package_name')['label'].to_dict() if 'package_name' in df.columns else {}, permission_columns
    except Exception as e:
        print(f"Warning: Failed to load malware dataset: {e}")
        return {}, []

def extract_apk_features(apk_path, malware_dataset=None, all_permissions=None):
    a, d, dx = AnalyzeAPK(apk_path)
    package_name = a.get_package()

    # Get basic features
    features = {
        "package_name": package_name,
        "apk_name": os.path.basename(apk_path),
    }
    
    # Extract all permissions
    permissions = a.get_permissions()
    extracted_permissions = []
    
    for perm in permissions:
        # Extract just the permission name from the full string
        perm_name = perm.split('.')[-1]
        extracted_permissions.append(perm_name)
        features[perm_name] = 1
    
    # If we have a predefined list, make sure all permissions are represented
    if all_permissions:
        for perm in all_permissions:
            if perm not in features:
                features[perm] = 0
    
    # Add label from dataset if available
    if malware_dataset and package_name in malware_dataset:
        features["label"] = malware_dataset[package_name]
    
    return features, extracted_permissions

# if __name__ == "__main__":
#     if len(sys.argv) < 2 or len(sys.argv) > 3:
#         print("Usage: python apk_feature_extractor.py path_to_apk [path_to_malware_csv]")
#         sys.exit(1)

#     apk_path = sys.argv[1]
    
#     # Load malware dataset if provided
#     malware_dataset = None
#     all_permissions = []
#     if len(sys.argv) == 3:
#         csv_path = sys.argv[2]
#         malware_dataset, all_permissions = load_malware_dataset(csv_path)
    
#     result, extracted_permissions = extract_apk_features(apk_path, malware_dataset, all_permissions)
    
#     # Convert to DataFrame and save as CSV
#     df = pd.DataFrame([result])
    
#     # Ensure all columns are ordered correctly
#     all_columns = ["package_name", "apk_name"] + (all_permissions if all_permissions else extracted_permissions)
#     if "label" in result:
#         all_columns.append("label")
    
#     df = df.reindex(columns=all_columns, fill_value=0)
    
#     # Save the result to a CSV file
#     output_file = os.path.basename(apk_path).replace(".apk", "_features.csv")
#     df.to_csv(output_file, index=False)

#     print(f"Features extracted and saved to {output_file}")
#     print(f"Found {len(extracted_permissions)} permissions in the APK.")
