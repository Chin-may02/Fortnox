import joblib

data = joblib.load('../models/final_phishing_model.joblib')
all_metrics = data.get('all_model_metrics', {})

print('Checking metrics in saved model file:')
print('=' * 60)

if not all_metrics:
    print("ERROR: No model metrics found in the file!")
    exit(1)

for name, metrics in all_metrics.items():
    print(f'\n{name}:')
    print(f'  Accuracy: {metrics.get("accuracy", 0):.4f} ({metrics.get("accuracy", 0)*100:.1f}%)')
    print(f'  Recall: {metrics.get("recall_phishing", 0):.4f} ({metrics.get("recall_phishing", 0)*100:.1f}%)')
    print(f'  F1: {metrics.get("f1_phishing", 0):.4f} ({metrics.get("f1_phishing", 0)*100:.1f}%)')

# Check if all are the same
values_list = list(all_metrics.values())
if len(values_list) > 1:
    first = values_list[0]
    all_same = all(
        m.get('accuracy') == first.get('accuracy') and
        m.get('recall_phishing') == first.get('recall_phishing') and
        m.get('f1_phishing') == first.get('f1_phishing')
        for m in values_list[1:]
    )
    
    print('\n' + '=' * 60)
    if all_same:
        print('WARNING: All models have IDENTICAL metrics!')
        print('   This might cause them to display the same in the UI.')
    else:
        print('SUCCESS: All models have DIFFERENT metrics - should display correctly!')