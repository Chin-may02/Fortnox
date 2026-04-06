"""
Generate a bar chart comparing all ML models with current metrics including AUC.
Reads metrics directly from the saved model file.
"""
import joblib
import matplotlib.pyplot as plt
import numpy as np
import os

# Load model file to get current metrics
print("Loading model file...")
model_file = os.environ.get('MODEL_FILE', '../models/final_phishing_model.joblib')
model_data = joblib.load(model_file)
all_model_metrics = model_data.get('all_model_metrics', {})

# Define model order (matching your current setup)
model_order = ['Linear SVM', 'Logistic Regression', 'Random Forest', 'XGBoost']

# Extract metrics for each model
models = []
accuracy_scores = []
recall_scores = []
f1_scores = []
auc_scores = []
time_scores = []

for model_name in model_order:
    if model_name in all_model_metrics:
        metrics = all_model_metrics[model_name]
        models.append(model_name)
        accuracy_scores.append(metrics.get('accuracy', 0) * 100)
        recall_scores.append(metrics.get('recall_phishing', 0) * 100)
        f1_scores.append(metrics.get('f1_phishing', 0) * 100)
        auc_scores.append(metrics.get('auc_score', 0) * 100)
        time_scores.append(metrics.get('training_time', 0))

# Create figure and axis with secondary y-axis for time
fig, ax1 = plt.subplots(figsize=(14, 7))

# Set up bar positions
x = np.arange(len(models))
width = 0.15  # Narrower bars to fit 5 metrics

# Create bars for percentage metrics (left y-axis)
bars1 = ax1.bar(x - 2*width, accuracy_scores, width, label='Accuracy', color='#4a5568', alpha=0.9)
bars2 = ax1.bar(x - width, recall_scores, width, label='Phishing Recall', color='#dc2626', alpha=0.9)
bars3 = ax1.bar(x, f1_scores, width, label='Phishing F1', color='#2563eb', alpha=0.9)
bars4 = ax1.bar(x + width, auc_scores, width, label='AUC', color='#16a34a', alpha=0.9)

# Create secondary y-axis for time
ax2 = ax1.twinx()
bars5 = ax2.bar(x + 2*width, time_scores, width, label='Time (s)', color='#f59e0b', alpha=0.9)

# Customize the left y-axis (percentages)
ax1.set_xlabel('Model', fontsize=12, fontweight='bold')
ax1.set_ylabel('Score (%)', fontsize=12, fontweight='bold', color='#1f2937')
ax1.set_xticks(x)
ax1.set_xticklabels([m.replace(' ', '\n') if len(m) > 12 else m for m in models], fontsize=10)
ax1.tick_params(axis='y', labelcolor='#1f2937')
ax1.grid(axis='y', alpha=0.3, linestyle='--')
ax1.set_ylim([75, 100])

# Customize the right y-axis (time)
ax2.set_ylabel('Time (seconds)', fontsize=12, fontweight='bold', color='#f59e0b')
ax2.tick_params(axis='y', labelcolor='#f59e0b')

# Title
ax1.set_title('FORTNOX: Model Performance Comparison', fontsize=14, fontweight='bold', pad=20)

# Combine legends from both axes
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10, framealpha=0.9)

# Add value labels on bars
def add_value_labels(bars, is_percentage=True):
    for bar in bars:
        height = bar.get_height()
        if is_percentage:
            label = f'{height:.1f}%'
        else:
            label = f'{height:.2f}s'
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                label,
                ha='center', va='bottom', fontsize=7, fontweight='bold')

def add_time_labels(bars):
    for bar in bars:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}s',
                ha='center', va='bottom', fontsize=7, fontweight='bold', color='#f59e0b')

add_value_labels(bars1)
add_value_labels(bars2)
add_value_labels(bars3)
add_value_labels(bars4)
add_time_labels(bars5)

# Adjust layout
plt.tight_layout()

# Save the figure
output_file = 'model_comparison_graph.png'
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"\n[OK] Graph saved as '{output_file}'")

# Display summary
print("\n" + "="*70)
print("Model Performance Summary:")
print("="*70)
for i, model in enumerate(models):
    print(f"\n{model}:")
    print(f"  Accuracy:    {accuracy_scores[i]:.1f}%")
    print(f"  Recall:      {recall_scores[i]:.1f}%")
    print(f"  F1-Score:    {f1_scores[i]:.1f}%")
    print(f"  AUC:         {auc_scores[i]:.1f}%")
    print(f"  Time (s):    {time_scores[i]:.4f}")

# Show the plot
plt.show()