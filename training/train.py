import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import joblib

# Load the dataset
file_path = "/Users/prajwalyadav03/Desktop/Prajwal/SSS/Serverless_security_architecture/Inventory-Management-System-Django-AWS/training/creditcard.csv"
df = pd.read_csv(file_path)

# Preprocess the dataset
df = df.sample(frac=1).reset_index(drop=True)  # Shuffle the dataset
data = df.drop(columns=['Class'])  # Features
labels = df['Class']  # Labels

# Split the dataset into training and testing sets
train_size = int(0.8 * len(df))
X_train, X_test = data[:train_size], data[train_size:]
y_train, y_test = labels[:train_size], labels[train_size:]

# Train the Isolation Forest model
model = IsolationForest(contamination=0.001, random_state=42)
model.fit(X_train)

# Save the model
joblib.dump(model, 'isolation_forest_model.pkl')

# Load the model (just to demonstrate)
model = joblib.load('isolation_forest_model.pkl')

# Predict anomalies
y_pred_train = model.predict(X_train)
y_pred_test = model.predict(X_test)

# Convert predictions to binary labels (1 for anomalies, 0 for normal data)
y_pred_train = np.where(y_pred_train == -1, 1, 0)
y_pred_test = np.where(y_pred_test == -1, 1, 0)

# Evaluate the model
print("Training Set Evaluation")
print(confusion_matrix(y_train, y_pred_train))
print(classification_report(y_train, y_pred_train))

print("Testing Set Evaluation")
print(confusion_matrix(y_test, y_pred_test))
print(classification_report(y_test, y_pred_test))


# Visualization

# Function to plot confusion matrix
def plot_confusion_matrix(y_true, y_pred, title):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title(title)
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.show()


# Plot confusion matrices
plot_confusion_matrix(y_train, y_pred_train, "Confusion Matrix for Training Set")
plot_confusion_matrix(y_test, y_pred_test, "Confusion Matrix for Testing Set")


# Function to plot ROC curve
def plot_roc_curve(y_true, y_scores, title):
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='blue', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
    plt.plot([0, 1], [0, 1], color='grey', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(title)
    plt.legend(loc="lower right")
    plt.show()


# Predict scores (anomalies have higher scores)
y_scores_train = model.decision_function(X_train)
y_scores_test = model.decision_function(X_test)

# Plot ROC curves
plot_roc_curve(y_train, y_scores_train, "ROC Curve for Training Set")
plot_roc_curve(y_test, y_scores_test, "ROC Curve for Testing Set")
