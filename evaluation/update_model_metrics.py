"""
Utility script to manually update model metrics in the saved model file.
This is useful if you want to set specific values for demonstration purposes.
"""
import joblib

def update_model_metrics():
    # Load the existing model
    data = joblib.load('../models/final_phishing_model.joblib')
    
    # Get current metrics
    print("Current metrics:")
    all_metrics = data.get('all_model_metrics', {})
    for name, metrics in all_metrics.items():
        print(f"\n{name}:")
        print(f"  Accuracy: {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.1f}%)")
        print(f"  Recall (phishing): {metrics.get('recall_phishing', 0):.4f} ({metrics.get('recall_phishing', 0)*100:.1f}%)")
        print(f"  F1 (phishing): {metrics.get('f1_phishing', 0):.4f} ({metrics.get('f1_phishing', 0)*100:.1f}%)")
    
    print("\n" + "="*60)
    print("Enter new metrics (values should be between 0.0 and 1.0):")
    print("="*60)
    
    # Update metrics for each model
    new_all_metrics = {}
    for model_name in ['Linear SVM', 'Logistic Regression', 'Random Forest', 'XGBoost']:
        if model_name not in all_metrics:
            continue
            
        print(f"\n{model_name}:")
        current = all_metrics[model_name]
        
        # Get new values (or use current if empty)
        acc_input = input(f"  Accuracy (current: {current.get('accuracy', 0):.4f}): ").strip()
        recall_input = input(f"  Phishing Recall (current: {current.get('recall_phishing', 0):.4f}): ").strip()
        f1_input = input(f"  Phishing F1 (current: {current.get('f1_phishing', 0):.4f}): ").strip()
        
        new_metrics = current.copy()
        
        if acc_input:
            try:
                new_metrics['accuracy'] = float(acc_input)
            except ValueError:
                print(f"    Invalid accuracy value, keeping current: {current.get('accuracy', 0):.4f}")
        
        if recall_input:
            try:
                new_metrics['recall_phishing'] = float(recall_input)
            except ValueError:
                print(f"    Invalid recall value, keeping current: {current.get('recall_phishing', 0):.4f}")
        
        if f1_input:
            try:
                new_metrics['f1_phishing'] = float(f1_input)
            except ValueError:
                print(f"    Invalid F1 value, keeping current: {current.get('f1_phishing', 0):.4f}")
        
        new_all_metrics[model_name] = new_metrics
    
    # Update the model data
    data['all_model_metrics'] = new_all_metrics
    
    # Update best_model_metrics if the active model changed
    active_model_name = data.get('model_name')
    if active_model_name in new_all_metrics:
        data['best_model_metrics'] = new_all_metrics[active_model_name]
    
    # Save the updated model
    backup_file = 'final_phishing_model.joblib.backup'
    print(f"\nCreating backup: {backup_file}")
    import shutil
    shutil.copy('final_phishing_model.joblib', backup_file)
    
    joblib.dump(data, 'final_phishing_model.joblib')
    print("✓ Model metrics updated successfully!")
    
    # Show updated metrics
    print("\nUpdated metrics:")
    for name, metrics in new_all_metrics.items():
        print(f"\n{name}:")
        print(f"  Accuracy: {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.1f}%)")
        print(f"  Recall (phishing): {metrics.get('recall_phishing', 0):.4f} ({metrics.get('recall_phishing', 0)*100:.1f}%)")
        print(f"  F1 (phishing): {metrics.get('f1_phishing', 0):.4f} ({metrics.get('f1_phishing', 0)*100:.1f}%)")

if __name__ == '__main__':
    update_model_metrics()

