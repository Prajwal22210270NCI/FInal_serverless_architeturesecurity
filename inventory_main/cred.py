import boto3
import json
import base64
from botocore.exceptions import ClientError
 
def get_secret():

# AWS Secrets Manager to use MySQL DB credentials stored there
    secret_name = "22209573_cpp_db"  
    region_name="eu-west-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
 
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Handle the exception based on the error code
        raise e
    else:
        # Decrypts secret using the associated KMS CMK
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secret_dict = json.loads(secret)
#            print("Retrieved secret:", secret_dict)  # Testing line
            return secret_dict
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(decoded_binary_secret)    
