# ml_model/anomaly_detection.py

import boto3
import logging
import joblib
import time

# Initialize CloudWatch Logs client
client = boto3.client('logs')

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define the Log Group and Log Stream
log_group_name = '/aws/lambda/inventory-manag-dev'
log_stream_name = ('news'
                   '')


def log_to_cloudwatch(message):
    try:
        # Get the current timestamp in milliseconds
        timestamp = int(round(time.time() * 1000))

        # Send a log event to CloudWatch
        response = client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    'timestamp': timestamp,
                    'message': message
                },
            ],
        )
        logger.info(f"Successfully logged message to CloudWatch: {message}")
    except Exception as e:
        logger.error(f"Failed to log message to CloudWatch: {e}")


# Load the model
model = joblib.load('ml_model/isolation_forest_model.pkl')


def detect_anomalies(data):
    # Run your anomaly detection logic here
    anomalies = model.predict(data)

    # Log anomalies to CloudWatch
    for anomaly in anomalies:
        if anomaly == 1:  # Assuming '1' indicates an anomaly
            log_to_cloudwatch(f"Anomaly detected in data: {data}")
        else:
            log_to_cloudwatch(f"Normal data: {data}")

    return anomalies
