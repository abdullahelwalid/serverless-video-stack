import dotenv


import boto3
import json
from botocore.exceptions import ClientError

dotenv.load_dotenv()


def get_all_secrets(secret_name: str, region_name: str = "ap-southeast-1") -> dict:
    """
    Retrieve and return all secrets from AWS Secrets Manager.

    :param secret_name: The name or ARN of the secret.
    :param region_name: AWS region where the secret is stored.
    :return: Dictionary of all secrets (parsed from JSON).
    """
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)

        if "SecretString" in response:
            secret_string = response["SecretString"]
            return json.loads(secret_string)
        else:
            # If the secret is binary (not common for JSON), decode it
            return json.loads(response["SecretBinary"].decode("utf-8"))

    except ClientError as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        raise


class Config(object):
    secrets = get_all_secrets(secret_name="video-stream/secret-key")
    # S3 and CloudFront settings
    BUCKET_NAME = secrets["BucketName"]
    CLOUDFRONT_DIST_URL = secrets["CloudfrontDistURL"]
    AWS_REGION = secrets["AWSRegion"]

    USE_CLOUDFRONT_SIGNED_URLS = False
    IS_PUBLIC = False

    COGNITO_REGION = AWS_REGION
    COGNITO_USER_POOL_ID = secrets["CognitoUserpoolID"]
    COGNITO_CLIENT_ID = secrets["CognitoClientID"]

    # Flask session settings
    SECRET_KEY = secrets["APIKey"]
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Optional: JWT settings for additional validation
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
