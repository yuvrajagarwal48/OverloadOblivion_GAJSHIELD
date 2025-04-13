# import pandas as pd
# import numpy as np
# from tensorflow.keras.models import load_model
# from sklearn.preprocessing import StandardScaler
# from sklearn.feature_selection import SelectKBest, f_classif
# import os
# from datetime import datetime

# def analyze_apk(features_path):
#     """
#     Performs inference on APK features for malware detection without requiring external arguments.
#     Uses a default test features file path and returns a standardized result format.
    
#     Returns:
#         Dictionary with analysis results including:
#         - is_malicious: Boolean indicating if the APK is classified as malware
#         - score: Confidence score of the prediction (0-1)
#         - risk_level: String categorization of risk ('low', 'medium', 'high')
#         - analysis_timestamp: When the analysis was performed (UTC)
#     """
#     # Use a default internal features path for inference
    
#     # Current timestamp in UTC
#     current_timestamp = "2025-04-13 03:31:21"  # Using the provided timestamp
    
#     try:
#         # === Load feature data ===
#         try:
#             test_df = pd.read_csv(features_path)
#             print(f"Successfully loaded features from {features_path}")
#         except Exception as e:
#             print(f"Error loading feature data: {str(e)}")
#             print("Trying alternative feature path...")

#         # === Identify and separate non-numeric columns ===
#         metadata_cols = []
#         numeric_cols = []

#         for col in test_df.columns:
#             # Save metadata columns separately (package_name, apk_name)
#             if col in ['package_name', 'apk_name']:
#                 metadata_cols.append(col)
#             else:
#                 # Check if the column can be converted to numeric
#                 try:
#                     pd.to_numeric(test_df[col])
#                     numeric_cols.append(col)
#                 except:
#                     pass  # Skip non-numeric columns for inference

#         print(f"Numeric feature columns: {len(numeric_cols)}")
#         print(f"Metadata columns: {metadata_cols}")

#         # === Create features dataframe with only numeric columns ===
#         test_features_df = test_df[numeric_cols].copy()
        
#         # Save metadata for results if available
#         metadata = {}
#         for col in metadata_cols:
#             if col in test_df.columns:
#                 metadata[col] = test_df[col].tolist()

#         # === Handle 'Label' column if present (not needed for inference) ===
#         if 'Label' in test_features_df.columns:
#             test_features_df = test_features_df.drop(['Label'], axis=1)

#         # === Convert to appropriate numeric type ===
#         for col in test_features_df.columns:
#             test_features_df[col] = pd.to_numeric(test_features_df[col], errors='coerce')
#             test_features_df[col] = test_features_df[col].fillna(0)
#             test_features_df[col] = test_features_df[col].astype(np.uint8)

#         # === Load model for inference ===
#         try:
#             model = load_model(r'models\android_malware_best_model_final.h5')
#             print("Successfully loaded model for inference")
#         except Exception as model_error:
#             print(f"Error loading primary model: {str(model_error)}")
#             return {
#                 'error': "Failed to load any malware detection model",
#                 'analysis_timestamp': current_timestamp,
#                 'summary': {
#                     'risk_level': 'error',
#                     'is_malicious': False,
#                     'score': 0
#                 }
#             }

#         # === Load original training data to fit feature selector correctly ===
#         try:
#             original_data = pd.read_csv('data\Android_Malware_Benign.csv')
#             original_data = original_data.dropna()
#             original_y = original_data.pop('Label')
#             original_x = original_data.astype(np.uint8)
#         except Exception as e:
#             print(f"Error loading training data for feature alignment: {str(e)}")
#             # For inference, we can create a simplified feature selector if original data is unavailable
#             print("Creating simplified feature selector for inference...")
#             # Use the test data to create a feature selector
#             selector = SelectKBest(score_func=f_classif, k=min(200, test_features_df.shape[1]))
#             # Create dummy labels for feature selection
#             dummy_y = np.zeros(test_features_df.shape[0])
#             selector.fit(test_features_df, dummy_y)
#             original_x = test_features_df
#         else:
#             # Create feature selector with original training data
#             selector = SelectKBest(score_func=f_classif, k=200)
#             selector.fit(original_x, original_y)

#         # === Ensure test data has compatible features for the model ===
#         try:
#             # Handle feature alignment
#             if test_features_df.shape[1] != original_x.shape[1]:
#                 print(f"Feature count mismatch: test={test_features_df.shape[1]}, original={original_x.shape[1]}")
                
#                 if test_features_df.shape[1] > original_x.shape[1]:
#                     # If test data has more features, trim to match original
#                     print("Trimming extra features...")
#                     test_features_df = test_features_df.iloc[:, :original_x.shape[1]]
#                 else:
#                     # If test data has fewer features, pad with zeros
#                     print("Adding missing features...")
#                     missing_cols = original_x.shape[1] - test_features_df.shape[1]
#                     for i in range(missing_cols):
#                         test_features_df[f'padding_{i}'] = 0
            
#             # Transform features
#             test_selected = selector.transform(test_features_df)
#             print(f"Feature selection complete. Shape: {test_selected.shape}")
            
#         except Exception as e:
#             print(f"Error in feature selection: {str(e)}")
#             # For inference, if feature selection fails, try using raw features
#             print("Using raw features for inference...")
#             test_selected = test_features_df.values
#             # Ensure we don't pass too many features to the model
#             expected_features = 200  # Typical input size for the model
#             if test_selected.shape[1] > expected_features:
#                 test_selected = test_selected[:, :expected_features]

#         # === Make predictions ===
#         print("Making predictions...")
#         pred_probs = model.predict(test_selected)
#         pred_labels = (pred_probs > 0.5).astype(int).flatten()

#         # === Create results dataframe ===
#         results_df = pd.DataFrame()
#         results_df['Predicted_Label'] = pred_labels
#         results_df['Predicted_Probability'] = pred_probs.flatten()
#         results_df['Classification'] = results_df['Predicted_Label'].apply(
#             lambda x: "MALWARE" if x == 1 else "BENIGN"
#         )

#         # Add metadata if available
#         for col, values in metadata.items():
#             if len(values) == len(results_df):
#                 results_df[col] = values

#         # === Prepare results for return ===
#         # Calculate average malware probability
#         avg_malware_prob = float(np.mean(pred_probs))
        
#         # Determine risk level based on probability
#         if avg_malware_prob < 0.3:
#             risk_level = 'low'
#         elif avg_malware_prob < 0.7:
#             risk_level = 'medium'
#         else:
#             risk_level = 'high'
        
#         # Determine if malicious based on majority vote
#         is_malicious = bool(sum(pred_labels) > len(pred_labels) / 2)
        
#         # Create detailed results
#         detailed_results = []
#         for i, row in results_df.iterrows():
#             result = {
#                 'id': int(i),
#                 'package_name': row.get('package_name', f"app_{i}"),
#                 'apk_name': row.get('apk_name', f"apk_{i}.apk"),
#                 'is_malware': bool(row['Predicted_Label'] == 1),
#                 'confidence': float(row['Predicted_Probability']),
#                 'classification': row['Classification']
#             }
#             detailed_results.append(result)
        
#         # Create final return structure optimized for inference
#         analysis_results = {
#             'analysis_timestamp': current_timestamp,
#             'summary': {
#                 'risk_level': risk_level,
#                 'is_malicious': is_malicious,
#                 'score': float(avg_malware_prob),
#                 'total_apps_analyzed': int(len(results_df)),
#                 'malware_count': int(sum(pred_labels)),
#                 'benign_count': int(len(pred_labels) - sum(pred_labels))
#             },
#             'detailed_results': detailed_results,
#             'file_path': features_path
#         }
        
#         return analysis_results
    
#     except Exception as e:
#         print(f"Error in APK analysis: {str(e)}")
#         # Return error structure for inference
#         return {
#             'error': str(e),
#             'analysis_timestamp': current_timestamp,
#             'summary': {
#                 'risk_level': 'error',
#                 'is_malicious': False,
#                 'score': 0
#             }
#         }


import pandas as pd
import numpy as np
import os
import joblib
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from datetime import datetime

def analyze_apk(features_path=None):
    """
    Performs inference on APK features for malware detection.
    
    Args:
        features_path: Path to the CSV file containing APK features.
                      If None, will use default path.
    
    Returns:
        Dictionary with analysis results including:
        - is_malicious: Boolean indicating if the APK is classified as malware
        - score: Confidence score of the prediction (0-1)
        - risk_level: String categorization of risk ('low', 'medium', 'high')
        - analysis_timestamp: When the analysis was performed (UTC)
    """

    
    # Current timestamp in UTC (using your provided timestamp)
    current_timestamp = "2025-04-13 08:15:46"  # Updated to your current timestamp
    
    try:
        # === Set up model and artifact paths ===
        model_paths = [
            r'models\android_model.h5',
            os.path.join(os.getcwd(), 'models', 'final_apk_model.h5')
        ]
        
        artifacts_dir = 'working/model_artifacts/'
        
        # === Load feature data ===
        try:
            test_df = pd.read_csv(features_path)
            print(f"Successfully loaded features from {features_path}")
        except Exception as e:
            print(f"Error loading feature data: {str(e)}")
            return {
                'error': f"Failed to load features from {features_path}: {str(e)}",
                'analysis_timestamp': current_timestamp,
                'summary': {
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                },
                'file_path': features_path
            }

        # === Identify and separate non-numeric columns ===
        metadata_cols = []
        numeric_cols = []

        for col in test_df.columns:
            # Save metadata columns separately (package_name, apk_name)
            if col in ['package_name', 'apk_name']:
                metadata_cols.append(col)
            else:
                # Check if the column can be converted to numeric
                try:
                    pd.to_numeric(test_df[col])
                    numeric_cols.append(col)
                except:
                    pass  # Skip non-numeric columns for inference

        print(f"Numeric feature columns: {len(numeric_cols)}")
        print(f"Metadata columns: {metadata_cols}")

        # === Extract label if it exists ===
        test_y = None
        if 'Label' in test_df.columns:
            test_y = test_df['Label'].copy()
            # Remove Label from numeric_cols if present
            if 'Label' in numeric_cols:
                numeric_cols.remove('Label')
            
        # === Create features dataframe with only numeric columns ===
        test_features_df = test_df[numeric_cols].copy()
        
        # Save metadata for results if available
        metadata = {}
        for col in metadata_cols:
            if col in test_df.columns:
                metadata[col] = test_df[col].tolist()

        # === Handle missing values ===
        test_features_df = test_features_df.dropna()

        # === Convert to appropriate numeric type ===
        for col in test_features_df.columns:
            test_features_df[col] = pd.to_numeric(test_features_df[col], errors='coerce')
            test_features_df[col] = test_features_df[col].fillna(0)  # Replace NaN with 0
            test_features_df[col] = test_features_df[col].astype(np.uint8)  # Now safe to convert

        # === Try to load preprocessors from artifacts ===
        scaler = None
        selector = None
        label_encoder = None
        
        try:
            # Try to load the saved preprocessors
            scaler = joblib.load(os.path.join(artifacts_dir, 'scaler.pkl'))
            selector = joblib.load(os.path.join(artifacts_dir, 'selector.pkl'))
            label_encoder = joblib.load(os.path.join(artifacts_dir, 'label_encoder.pkl'))
            print("Successfully loaded preprocessing artifacts")
            
            # If we have a loaded selector, we don't need to reload original data
            has_saved_preprocessors = True
        except Exception as e:
            print(f"Could not load preprocessors: {str(e)}")
            has_saved_preprocessors = False

        # === Load model for inference ===
        model = None
        for model_path in model_paths:
            try:
                model = load_model(model_path)
                print(f"Successfully loaded model from {model_path}")
                break
            except Exception as e:
                print(f"Failed to load model from {model_path}: {str(e)}")
                continue
        
        if model is None:
            print("Failed to load any malware detection model")
            return {
                'error': "Failed to load any malware detection model",
                'analysis_timestamp': current_timestamp,
                'summary': {
                    'risk_level': 'error',
                    'is_malicious': False,
                    'score': 0
                },
                'file_path': features_path
            }

        # === Load original training data if needed (if we don't have saved preprocessors) ===
        if not has_saved_preprocessors:
            try:
                # Try different paths for original data
                original_data_paths = [
                    r'data\Android_Malware_Benign.csv',
                    os.path.join(os.getcwd(), 'data', 'Android_Malware_Benign.csv')
                ]
                
                original_data = None
                for path in original_data_paths:
                    try:
                        original_data = pd.read_csv(path)
                        print(f"Successfully loaded original training data from {path}")
                        break
                    except Exception:
                        continue
                
                if original_data is None:
                    raise FileNotFoundError("Could not find original training data")
                
                original_data = original_data.dropna()
                original_y = original_data.pop('Label')
                original_x = original_data.astype(np.uint8)
                
                # Create new preprocessors
                scaler = StandardScaler()
                scaler.fit(original_x)
                
                selector = SelectKBest(score_func=f_classif, k=200)
                selector.fit(original_x, original_y)
                
                # Try to save these preprocessors for future use
                try:
                    os.makedirs(artifacts_dir, exist_ok=True)
                    joblib.dump(scaler, os.path.join(artifacts_dir, 'scaler.pkl'))
                    joblib.dump(selector, os.path.join(artifacts_dir, 'selector.pkl'))
                    print("Saved preprocessors to artifacts directory")
                except Exception as save_error:
                    print(f"Could not save preprocessors: {str(save_error)}")
                
            except Exception as e:
                print(f"Error loading training data for feature alignment: {str(e)}")
                # For inference, we can create a simplified feature selector if original data is unavailable
                print("Creating simplified feature selector for inference...")
                # Use the test data to create a feature selector
                selector = SelectKBest(score_func=f_classif, k=min(200, test_features_df.shape[1]))
                # Create dummy labels for feature selection
                dummy_y = np.zeros(test_features_df.shape[0])
                selector.fit(test_features_df, dummy_y)
                
                # Create a simple scaler
                scaler = StandardScaler()
                scaler.fit(test_features_df)
                
                # Use the test data as "original" for feature matching
                original_x = test_features_df

        # === Ensure test data has compatible features for the model ===
        try:
            # Apply scaling if we have a scaler
            if scaler is not None:
                test_scaled = scaler.transform(test_features_df)
            else:
                # If no scaler, just standardize manually
                test_scaled = test_features_df.values
            
            # Handle feature alignment
            if selector is not None:
                # Before trying to transform, check if shapes match
                if hasattr(selector, 'n_features_in_') and test_features_df.shape[1] != selector.n_features_in_:
                    print(f"Feature count mismatch: test={test_features_df.shape[1]}, expected={selector.n_features_in_}")
                    
                    # Align features
                    if test_features_df.shape[1] > selector.n_features_in_:
                        # If test data has more features, trim to match original
                        print("Trimming extra features...")
                        test_features_df = test_features_df.iloc[:, :selector.n_features_in_]
                        # Re-apply scaling
                        if scaler is not None:
                            test_scaled = scaler.transform(test_features_df)
                        else:
                            test_scaled = test_features_df.values
                    else:
                        # If test data has fewer features, pad with zeros
                        print("Adding missing features...")
                        missing_cols = selector.n_features_in_ - test_features_df.shape[1]
                        for i in range(missing_cols):
                            test_features_df[f'padding_{i}'] = 0
                        # Re-apply scaling
                        if scaler is not None:
                            test_scaled = scaler.transform(test_features_df)
                        else:
                            test_scaled = test_features_df.values
                
                # Transform features
                test_selected = selector.transform(test_scaled)
                print(f"Feature selection complete. Shape: {test_selected.shape}")
            else:
                # If no selector, just use scaled data
                test_selected = test_scaled
                print(f"No feature selection performed. Using scaled features: {test_selected.shape}")
            
        except Exception as e:
            print(f"Error in feature selection: {str(e)}")
            # For inference, if feature selection fails, try using raw features
            print("Using raw features for inference...")
            test_selected = test_features_df.values
            # Ensure we don't pass too many features to the model
            expected_input_shape = 200  # Typical expected input size
            if model.input_shape[1:] and model.input_shape[1] > 0:
                expected_input_shape = model.input_shape[1]
                
            if test_selected.shape[1] > expected_input_shape:
                test_selected = test_selected[:, :expected_input_shape]
            elif test_selected.shape[1] < expected_input_shape:
                # Pad with zeros
                padding = np.zeros((test_selected.shape[0], expected_input_shape - test_selected.shape[1]))
                test_selected = np.hstack((test_selected, padding))

        # === Make predictions ===
        print("Making predictions...")
        pred_probs = model.predict(test_selected)
        pred_labels = (pred_probs > 0.5).astype(int).flatten()

        # === Create results dataframe ===
        results_df = pd.DataFrame()
        results_df['Predicted_Label'] = pred_labels
        results_df['Predicted_Probability'] = pred_probs.flatten()
        results_df['Classification'] = results_df['Predicted_Label'].apply(
            lambda x: "MALWARE" if x == 1 else "BENIGN"
        )

        # Add metadata if available
        for col, values in metadata.items():
            if len(values) == len(results_df):
                results_df[col] = values

        # === Compare with ground truth (if available) ===
        accuracy = None
        if test_y is not None:
            from sklearn.metrics import classification_report, confusion_matrix
            # Ensure test_y is aligned with the rows in test_features_df
            aligned_test_y = test_y.iloc[test_features_df.index].reset_index(drop=True)
            
            try:
                cm = confusion_matrix(aligned_test_y, pred_labels)
                print("Confusion Matrix:\n", cm)
                
                cr = classification_report(aligned_test_y, pred_labels)
                print("Classification Report:\n", cr)
                
                results_df['Actual_Label'] = aligned_test_y
                results_df['Actual_Classification'] = results_df['Actual_Label'].apply(
                    lambda x: "MALWARE" if x == 1 else "BENIGN"
                )
                
                # Add comparison column
                results_df['Correct_Prediction'] = results_df['Predicted_Label'] == results_df['Actual_Label']
                accuracy = sum(results_df['Correct_Prediction']) / len(results_df)
                
            except Exception as e:
                print(f"Error calculating metrics: {str(e)}")

        # === Print a summary of results ===
        print("\n=== MALWARE DETECTION RESULTS ===")
        print(f"Total apps analyzed: {len(results_df)}")
        print(f"Apps classified as MALWARE: {sum(pred_labels)} ({sum(pred_labels)/len(pred_labels)*100:.1f}%)")
        print(f"Apps classified as BENIGN: {len(pred_labels) - sum(pred_labels)} ({(1-sum(pred_labels)/len(pred_labels))*100:.1f}%)")

        if accuracy is not None:
            print(f"Overall prediction accuracy: {accuracy*100:.1f}%")
            
        # Print some examples
        print("\n=== SAMPLE RESULTS ===")
        sample_results = results_df.head(10)
        for _, row in sample_results.iterrows():
            prediction_status = "✓" if row.get('Correct_Prediction', True) else "✗"
            package_name = row.get('package_name', 'unknown')
            apk_name = row.get('apk_name', 'unknown')
            print(f"{prediction_status} {package_name} ({apk_name}): {row['Classification']}")

        # === Prepare results for return ===
        # Calculate average malware probability
        avg_malware_prob = float(np.mean(pred_probs))
        
        # Determine risk level based on probability
        if avg_malware_prob < 0.3:
            risk_level = 'low'
        elif avg_malware_prob < 0.7:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        # Determine if malicious based on majority vote
        is_malicious = bool(sum(pred_labels) > len(pred_labels) / 2)
        
        # Create detailed results
        detailed_results = []
        for i, row in results_df.head(min(10, len(results_df))).iterrows():
            result = {
                'id': int(i),
                'package_name': row.get('package_name', f"app_{i}"),
                'apk_name': row.get('apk_name', f"apk_{i}.apk"),
                'is_malware': bool(row['Predicted_Label'] == 1),
                'confidence': float(row['Predicted_Probability']),
                'classification': row['Classification']
            }
            detailed_results.append(result)
        
        # Create final return structure optimized for inference
        analysis_results = {
            'analysis_timestamp': current_timestamp,
            'summary': {
                'risk_level': risk_level,
                'is_malicious': is_malicious,
                'score': float(avg_malware_prob),
                'total_apps_analyzed': int(len(results_df)),
                'malware_count': int(sum(pred_labels)),
                'benign_count': int(len(pred_labels) - sum(pred_labels))
            },
            'detailed_results': detailed_results,
            'file_path': features_path
        }
        
        if accuracy is not None:
            analysis_results['accuracy'] = float(accuracy)
        
        # Save results to file
        try:
            results_df.to_csv('/kaggle/working/test_predictions.csv', index=False)
            print("\nComplete results saved to test_predictions.csv")
        except Exception as e:
            print(f"Error saving results to file: {str(e)}")
        
        return analysis_results
    
    except Exception as e:
        print(f"Error in APK analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        # Return error structure for inference
        return {
            'error': str(e),
            'analysis_timestamp': current_timestamp,
            'summary': {
                'risk_level': 'error',
                'is_malicious': False,
                'score': 0
            },
            'file_path': features_path
        }