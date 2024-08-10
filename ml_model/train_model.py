import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Sample data: replace with actual serverless environment data
data = {
    'feature1': np.random.normal(0, 1, 1000),
    'feature2': np.random.normal(0, 1, 1000)
}

# Corrected line with missing parenthesis
df = pd.DataFrame(data)

# Introduce some anomalies for demonstration
anomalies = {
    'feature1': np.random.normal(5, 1, 20),
    'feature2': np.random.normal(5, 1, 20)
}
anomalies_df = pd.DataFrame(anomalies)
df = pd.concat([df, anomalies_df], ignore_index=True)

# Define the Isolation Forest model
model = IsolationForest(contamination=0.02, random_state=42)

# Fit the model
model.fit(df)

# Predict anomalies
df['anomaly'] = model.predict(df)

# -1 for anomalies, 1 for normal data; map to 0 (normal) and 1 (anomaly)
df['anomaly'] = df['anomaly'].map({1: 0, -1: 1})

# Show detected anomalies
anomalies_detected = df[df['anomaly'] == 1]
print("Detected anomalies:")
print(anomalies_detected)

# Optionally save the anomalies to a file
anomalies_detected.to_csv('anomalies_detected.csv', index=False)
