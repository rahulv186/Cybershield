import joblib
import os


MODEL_FILES = [
    "models/binary_random_forest_dedup.joblib",
    "models/binary_xgboost.joblib",
    "models/multiclass_random_forest.joblib",
    "models/multiclass_xgboost.joblib",
    "models/multiclass_class_mapping.joblib",
]


print("Checking CyberShield ML models...\n")

for model_file in MODEL_FILES:

    print(f"Loading: {model_file}")

    if not os.path.exists(model_file):
        print("ERROR: File not found")
        raise SystemExit(1)

    model = joblib.load(model_file)

    print("OK")


print("\nAll ML model files loaded successfully.")
print("ML delivery package is valid.")