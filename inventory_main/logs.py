from botocore.exceptions import ClientError
import boto3

def log_activity():

    try:
        client = boto3.client('cloudtrail', region_name='eu-west-1')
        client.start_logging(Name='DjangoApplicationTrail')
        print('Started Logs')
    except ClientError as e:
        # Handle any errors that may occur
        print(e)
