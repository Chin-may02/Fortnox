"""
Generate a Quantitative Performance Summary table for all ML models.
Creates a formatted table similar to academic/research papers.
"""
import joblib
import pandas as pd
import os

# Load model file to get current metrics
print("Loading model file...")
model_file = os.environ.get('MODEL_FILE', '../models/final_phishing_model.joblib')
model_data = joblib.load(model_file)
all_model_metrics = model_data.get('all_model_metrics', {})

# Define model order (matching your current setup)
model_order = ['Linear SVM', 'Logistic Regression', 'Random Forest', 'XGBoost']

# Prepare data for table
table_data = []

for model_name in model_order:
    if model_name in all_model_metrics:
        metrics = all_model_metrics[model_name]
        
        # Extract metrics
        accuracy = metrics.get('accuracy', 0)
        precision = metrics.get('precision_phishing', 0)
        recall = metrics.get('recall_phishing', 0)
        f1 = metrics.get('f1_phishing', 0)
        training_time = metrics.get('training_time', 0)
        
        table_data.append({
            'Model': model_name,
            'Accuracy (%)': f"{accuracy * 100:.2f}",
            'Precision': f"{precision:.4f}",
            'Recall': f"{recall:.4f}",
            'F1-Score': f"{f1:.4f}",
            'Time (s)': f"{training_time:.4f}"
        })

# Create DataFrame
df = pd.DataFrame(table_data)

# Display the table with better formatting
print("\n" + "="*90)
print(" " * 30 + "QUANTITATIVE PERFORMANCE SUMMARY")
print("="*90)

# Format the table with proper alignment
formatted_table = df.to_string(index=False)
print("\n" + formatted_table)
print("\n" + "="*90)

# Save to CSV
csv_file = 'performance_summary.csv'
df.to_csv(csv_file, index=False)
print(f"\n[OK] Table saved as '{csv_file}'")

# Also create a formatted text file
txt_file = 'performance_summary.txt'
with open(txt_file, 'w') as f:
    f.write("="*90 + "\n")
    f.write(" " * 30 + "QUANTITATIVE PERFORMANCE SUMMARY\n")
    f.write("="*90 + "\n\n")
    f.write(df.to_string(index=False))
    f.write("\n\n" + "="*90 + "\n")

print(f"[OK] Table saved as '{txt_file}'")

# Display summary statistics
print("\n" + "-"*80)
print("Summary Statistics:")
print("-"*80)
print(f"Best Accuracy: {df.loc[df['Accuracy (%)'].astype(float).idxmax(), 'Model']} ({df['Accuracy (%)'].astype(float).max()}%)")
print(f"Best Precision: {df.loc[df['Precision'].astype(float).idxmax(), 'Model']} ({df['Precision'].astype(float).max()})")
print(f"Best Recall: {df.loc[df['Recall'].astype(float).idxmax(), 'Model']} ({df['Recall'].astype(float).max()})")
print(f"Best F1-Score: {df.loc[df['F1-Score'].astype(float).idxmax(), 'Model']} ({df['F1-Score'].astype(float).max()})")
print(f"Fastest Training: {df.loc[df['Time (s)'].astype(float).idxmin(), 'Model']} ({df['Time (s)'].astype(float).min()}s)")
print(f"Slowest Training: {df.loc[df['Time (s)'].astype(float).idxmax(), 'Model']} ({df['Time (s)'].astype(float).max()}s)")





