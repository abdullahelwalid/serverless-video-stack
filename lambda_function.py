import json
import urllib
import jwt


import boto3
import json
from botocore.exceptions import ClientError


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


# Flask session settings
SECRET_KEY = ""
API_URL = ""


def handle_cors_preflight(request):
    """Handle CORS preflight OPTIONS requests"""
    headers = request.get("headers", {})
    origin = None

    # Get origin from headers
    if "origin" in headers:
        origin = headers["origin"][0]["value"]

    # List of allowed origins
    allowed_origins = [API_URL]

    cors_origin = "*"
    if origin and origin in allowed_origins:
        cors_origin = origin
    if cors_origin == "*":
        return _forbidden("Origin not allowed")

    return {
        "status": "200",
        "statusDescription": "OK",
        "headers": {
            "access-control-allow-origin": [
                {"key": "Access-Control-Allow-Origin", "value": cors_origin}
            ],
            "access-control-allow-methods": [
                {"key": "Access-Control-Allow-Methods", "value": "GET, HEAD, OPTIONS"}
            ],
            "access-control-allow-headers": [
                {
                    "key": "Access-Control-Allow-Headers",
                    "value": "Accept, Accept-Language, Content-Language, Content-Type, Authorization, Range, Cookie, X-Requested-With",
                }
            ],
            "access-control-allow-credentials": [
                {"key": "Access-Control-Allow-Credentials", "value": "true"}
            ],
            "access-control-max-age": [
                {"key": "Access-Control-Max-Age", "value": "3600"}
            ],
            "content-type": [{"key": "Content-Type", "value": "text/plain"}],
            "content-length": [{"key": "Content-Length", "value": "0"}],
        },
    }


def lambda_handler(event, context):
    request = event["Records"][0]["cf"]["request"]
    headers = request.get("headers", {})

    # Get origin for CORS
    global SECRET_KEY, API_URL
    if SECRET_KEY == "" or API_URL == "":
        secrets = get_all_secrets(secret_name="video-stream/secret-key")
        SECRET_KEY = secrets["APIKey"]
        API_URL = f"https://{secrets["DomainName"]}"
        print("Fetching Secret From Cache")
    print("SECRET Fetched")

    origin = None
    if "origin" in headers:
        origin = headers["origin"][0]["value"]

    # Handle CORS preflight requests
    if request["method"] == "OPTIONS":
        return handle_cors_preflight(request)

    uri = request["uri"]
    querystring = request.get("querystring", "")

    # Extract ?token=... from query string
    token = None
    params = urllib.parse.parse_qs(querystring)
    if "token" in params:
        token = params["token"][0]

    if not token:
        print("Missing token")
        return _forbidden("Missing token")

    try:
        print("Fetching Secret")
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        resource_sub = decoded.get("sub")

        if not resource_sub:
            return _forbidden("Token missing 'sub' claim")

        # Validate resource in URI matches token's subject
        if resource_sub not in uri:
            return _forbidden("Token 'sub' does not match requested resource")

        # Token is valid and authorized
        return request

    except jwt.ExpiredSignatureError:
        return _forbidden("Token expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return _forbidden(f"Invalid token: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return _forbidden("Authorization error")


def _forbidden(reason):
    """Return 403 Forbidden response"""
    return {"status": "403", "statusDescription": "Forbidden", "body": reason}
