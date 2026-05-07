"""
retrain.py  —  Run this once to regenerate pickle/model.pkl
Usage:  python retrain.py
"""
import pickle
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics

# Load dataset (30 feature columns + 1 label column)
df = pd.read_csv("phishing.csv")

# Drop the index column if present
if "Index" in df.columns:
    df = df.drop(columns=["Index"])

X = df.drop(columns=["class"])
y = df["class"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

gbc = GradientBoostingClassifier(
    n_estimators=300,
    max_depth=4,
    random_state=42,
)
gbc.fit(X_train, y_train)

y_pred = gbc.predict(X_test)
accuracy = metrics.accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

# Save the retrained model
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(gbc, f)

print("Model saved to pickle/model.pkl — you can now run app.py")
