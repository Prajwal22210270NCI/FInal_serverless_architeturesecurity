import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Create synthetic data for demonstration
rng = np.random.RandomState(42)
X = 0.3 * rng.randn(100, 2)
X_train = np.r_[X + 2, X - 2]
X_test = 0.3 * rng.randn(20, 2)
X_outliers = rng.uniform(low=-4, high=4, size=(20, 2))

# Combine the training and outlier data
X_train = np.concatenate([X_train, X_outliers], axis=0)

# Create the Isolation Forest model
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

# Save the model to a file
joblib.dump(model, 'isolation_forest_model.pkl')

print("Model trained and saved as isolation_forest_model.pkl")
