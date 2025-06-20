from datetime import datetime, timezone
from flask import (
    Flask,
    Response,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    make_response,
)
import boto3
import requests
import jwt
from jwt.algorithms import RSAAlgorithm
import json
from functools import wraps
from config import Config

# Initialize AWS clients
s3 = boto3.client("s3", region_name=Config.AWS_REGION)
cognito_client = boto3.client("cognito-idp", region_name=Config.AWS_REGION)

app = Flask(__name__)
app.config.from_object(Config)

# Cache for Cognito public keys
cached_keys = None
keys_cache_time = None


import jwt
import datetime
from typing import Any, Dict


def generate_token(resource_key: str, expires_in_minutes: int = 30) -> str:
    """
    Generates a JWT token valid for a specified number of minutes and tied to a resource.

    :param secret_key: The secret key used to sign the token.
    :param resource_key: The identifier of the resource being requested.
    :param expires_in_minutes: Token validity duration in minutes.
    :return: Encoded JWT token as a string.
    """
    now = datetime.datetime.utcnow()
    payload: Dict[str, Any] = {
        "sub": resource_key,  # subject: resource being accessed
        "iat": now,  # issued at
        "exp": now + datetime.timedelta(minutes=expires_in_minutes),
    }

    token = jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")
    return token


def get_cognito_public_keys():
    """Get and cache Cognito public keys for JWT verification"""
    global cached_keys, keys_cache_time

    # Cache keys for 1 hour
    if (
        cached_keys
        and keys_cache_time
        and (datetime.datetime.now() - keys_cache_time).seconds < 3600
    ):
        return cached_keys

    try:
        jwks_url = f"https://cognito-idp.{Config.AWS_REGION}.amazonaws.com/{Config.COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()

        cached_keys = {
            key["kid"]: RSAAlgorithm.from_jwk(json.dumps(key)) for key in jwks["keys"]
        }
        keys_cache_time = datetime.datetime.now()
        return cached_keys
    except Exception as e:
        print(f"Error fetching Cognito public keys: {e}")
        return {}


def verify_jwt_token(token):
    """Verify JWT token from Cognito"""
    try:
        # Get public keys
        keys = get_cognito_public_keys()
        if not keys:
            return None

        # Get key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header.get("kid")

        if not key_id or key_id not in keys:
            return None

        # Verify token
        issuer = f"https://cognito-idp.{Config.AWS_REGION}.amazonaws.com/{Config.COGNITO_USER_POOL_ID}"
        decoded_token = jwt.decode(
            token,
            key=keys[key_id],
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False},
        )

        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None


def refresh_access_token(refresh_token):
    """Refresh access token using refresh token"""
    try:
        response = cognito_client.admin_initiate_auth(
            UserPoolId=Config.COGNITO_USER_POOL_ID,
            ClientId=Config.COGNITO_CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
            },
        )

        auth_result = response["AuthenticationResult"]
        new_access_token = auth_result["AccessToken"]
        new_id_token = auth_result["IdToken"]

        # Note: Refresh token might not be returned in refresh flow
        # If it is, it will be a new refresh token
        new_refresh_token = auth_result.get("RefreshToken", refresh_token)

        return {
            "access_token": new_access_token,
            "id_token": new_id_token,
            "refresh_token": new_refresh_token,
            "success": True,
        }

    except cognito_client.exceptions.NotAuthorizedException as e:
        print(f"Refresh token invalid or expired: {e}")
        return {"success": False, "error": "refresh_token_invalid"}
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return {"success": False, "error": str(e)}


def set_auth_cookies(response, access_token, id_token, refresh_token):
    """Helper function to set authentication cookies"""
    cookie_options = {
        "max_age": 2592000,  # 30 days (match refresh token expiry)
        "secure": True,  # Only send over HTTPS in production
        "httponly": True,  # Prevent XSS attacks
        "samesite": "Lax",  # CSRF protection
    }

    # In development, don't require HTTPS
    if app.debug:
        cookie_options["secure"] = False

    response.set_cookie("access_token", access_token, **cookie_options)
    response.set_cookie("id_token", id_token, **cookie_options)
    response.set_cookie("refresh_token", refresh_token, **cookie_options)


def clear_auth_cookies(response):
    """Helper function to clear authentication cookies"""
    response.delete_cookie("access_token")
    response.delete_cookie("id_token")
    response.delete_cookie("refresh_token")


def get_user_info_from_cookies():
    """Extract user info from cookies with token refresh capability"""
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if not access_token:
        print("Access Token not found")
        return None

    # Try to verify the current access token
    decoded_token = verify_jwt_token(access_token)

    if decoded_token:
        # Token is valid, return user info
        return {
            "username": decoded_token.get("username"),
            "email": decoded_token.get("email"),
            "sub": decoded_token.get("sub"),
            "access_token": access_token,
        }
    print("Decode Token Failed")

    # Token is invalid/expired, try to refresh if we have a refresh token
    if refresh_token:
        print("Refreshing Token")
        refresh_result = refresh_access_token(refresh_token)

        if refresh_result["success"]:
            # Successfully refreshed, verify the new token
            new_decoded_token = verify_jwt_token(refresh_result["access_token"])

            if new_decoded_token:
                print("Token successfully refreshed")
                return {
                    "username": new_decoded_token.get("username"),
                    "email": new_decoded_token.get("email"),
                    "sub": new_decoded_token.get("sub"),
                    "access_token": refresh_result["access_token"],
                    "needs_cookie_update": True,  # Flag to update cookies
                    "new_tokens": refresh_result,
                }
        print("Token Refresh Failed")
    print("Refresh Token is invalid or not found")

    # Could not refresh or no refresh token available
    return None


def login_required(f):
    """Decorator to require authentication with automatic token refresh"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_info = get_user_info_from_cookies()

        if not user_info:
            print("No valid authentication found, redirecting to login")
            response = make_response(redirect(url_for("login")))
            clear_auth_cookies(response)
            flash("Session expired. Please log in again.", "warning")
            return response

        # Check if we need to update cookies with refreshed tokens
        if user_info.get("needs_cookie_update"):
            print("Updating cookies with refreshed tokens")

            # Get the current response by calling the wrapped function first
            result = f(*args, **kwargs)

            # If result is already a Response object, use it; otherwise create one
            if isinstance(result, Response):
                response = result
            else:
                response = make_response(result)

            # Update cookies with new tokens
            new_tokens = user_info["new_tokens"]
            set_auth_cookies(
                response,
                new_tokens["access_token"],
                new_tokens["id_token"],
                new_tokens["refresh_token"],
            )

            return response

        return f(*args, **kwargs)

    return decorated_function


def get_video_metadata(file_key):
    """Get video file metadata from S3"""
    try:
        response = s3.head_object(Bucket=Config.BUCKET_NAME, Key=file_key)
        return {
            "size": response.get("ContentLength", 0),
            "content_type": response.get("ContentType", "video/mp4"),
            "last_modified": response.get("LastModified"),
        }
    except Exception as e:
        print(f"Error getting metadata for {file_key}: {e}")
        return {"size": 0, "content_type": "video/mp4", "last_modified": None}


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login route"""
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template("login.html")

    try:
        # Authenticate with Cognito
        response = cognito_client.admin_initiate_auth(
            UserPoolId=Config.COGNITO_USER_POOL_ID,
            ClientId=Config.COGNITO_CLIENT_ID,
            AuthFlow="ADMIN_NO_SRP_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        print("AUTH Response: ", response)

        # Get tokens from response
        auth_result = response["AuthenticationResult"]
        access_token = auth_result["AccessToken"]
        id_token = auth_result["IdToken"]
        refresh_token = auth_result["RefreshToken"]

        # Create response and set cookies
        response = make_response(redirect(url_for("index")))
        set_auth_cookies(response, access_token, id_token, refresh_token)

        flash("Login successful!", "success")
        return response

    except cognito_client.exceptions.NotAuthorizedException:
        flash("Invalid username or password.", "error")
    except cognito_client.exceptions.UserNotConfirmedException:
        flash("User account is not confirmed.", "error")
    except Exception as e:
        print(f"Login error: {e}")
        flash("Login failed. Please try again.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout route"""
    response = make_response(redirect(url_for("login")))
    clear_auth_cookies(response)
    flash("You have been logged out.", "info")
    return response


@app.route("/")
@login_required
def index():
    """Main page showing video list"""
    try:
        response = s3.list_objects_v2(Bucket=Config.BUCKET_NAME)
        files = []

        for obj in response.get("Contents", []):
            if obj["Key"].endswith(".mp4"):
                # Get file size for display
                file_size = obj.get("Size", 0)
                file_size_mb = (
                    round(file_size / (1024 * 1024), 1) if file_size > 0 else 0
                )
                thumb_key = obj["Key"].rsplit(".", 1)[0] + ".jpg"
                token = generate_token(resource_key=thumb_key)
                thumb_url = (
                    f"https://{Config.CLOUDFRONT_DIST_URL}/{thumb_key}?token={token}"
                )

                files.append(
                    {
                        "key": obj["Key"],
                        "size": file_size,
                        "size_mb": file_size_mb,
                        "last_modified": obj.get("LastModified"),
                        "thumb": thumb_url,
                    }
                )

        # Sort by last modified (newest first)
        files.sort(
            key=lambda x: x["last_modified"]
            or datetime.datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        # Get user info from cookies
        user_info = get_user_info_from_cookies()

        return render_template("index.html", files=files, user_info=user_info)

    except Exception as e:
        print(f"Error listing files: {e}")
        flash("Error loading video list.", "error")
        user_info = get_user_info_from_cookies()
        return render_template("index.html", files=[], user_info=user_info)


@app.route("/proxy/image")
@login_required
def proxy_image():
    user_info = get_user_info_from_cookies()
    access_token = user_info.get("access_token") if user_info else None

    # The actual image URL you want to fetch
    image_url = request.args.get("url", default=None, type=str)
    if not image_url or not access_token:
        return Response("Unauthorized", status=401)

    # Send request with Authorization header
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(image_url, headers=headers, stream=True)

    # Return the response to the browser with the original content type
    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type"),
    )


@app.route("/watch")
@login_required
def watch():
    """Video watch page"""
    file_key = request.args.get("file")
    if not file_key:
        flash("No file specified.", "error")
        return redirect(url_for("index"))

    # Get video metadata
    metadata = get_video_metadata(file_key)

    token = generate_token(resource_key=file_key)
    # Use direct CloudFront URL (authentication handled by Lambda@Edge)
    video_url = f"https://{Config.CLOUDFRONT_DIST_URL}/{file_key}?token={token}"

    # Get user info from cookies
    user_info = get_user_info_from_cookies()

    return render_template(
        "watch.html",
        file_key=file_key,
        video_url=video_url,
        file_size_mb=(
            round(metadata["size"] / (1024 * 1024), 1) if metadata["size"] > 0 else 0
        ),
        user_info=user_info,
    )


def get_thumbnail_url(file_key):
    """Get thumbnail URL"""
    thumb_key = file_key.rsplit(".", 1)[0] + ".jpg"

    try:
        s3.head_object(Bucket=Config.BUCKET_NAME, Key=thumb_key)
        return f"https://{Config.CLOUDFRONT_DIST_URL}/{thumb_key}"
    except s3.exceptions.ClientError:
        return None


@app.route("/api/token")
@login_required
def get_token():
    """API endpoint to get current access token for CloudFront requests"""
    user_info = get_user_info_from_cookies()
    access_token = user_info.get("access_token") if user_info else None

    return jsonify(
        {
            "access_token": access_token,
            "expires_in": 3600,  # Tokens typically expire in 1 hour
        }
    )


@app.route("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
    }


# Add CORS headers for better video streaming
@app.after_request
def after_request(response):
    response.headers.add("Accept-Ranges", "bytes")
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Range, Authorization")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response


# Template functions
app.jinja_env.globals.update(get_thumbnail_url=get_thumbnail_url)

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
