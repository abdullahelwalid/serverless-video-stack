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
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None


def get_user_info_from_cookies():
    """Extract user info from cookies"""
    access_token = request.cookies.get("access_token")
    if not access_token:
        return None

    decoded_token = verify_jwt_token(access_token)
    if not decoded_token:
        return None

    return {
        "username": decoded_token.get("username"),
        "email": decoded_token.get("email"),
        "sub": decoded_token.get("sub"),
        "access_token": access_token,
    }


def login_required(f):
    """Decorator to require authentication"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user has valid token in cookies
        access_token = request.cookies.get("access_token")
        if not access_token:
            print("Access Token not in cookies")
            return redirect(url_for("login"))

        # Verify token
        decoded_token = verify_jwt_token(access_token)
        if not decoded_token:
            print("Invalid or expired token")
            response = make_response(redirect(url_for("login")))
            # Clear cookies
            response.delete_cookie("access_token")
            response.delete_cookie("id_token")
            response.delete_cookie("refresh_token")
            flash("Session expired. Please log in again.", "warning")
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

        # Set cookies with security options
        cookie_options = {
            "max_age": 3600,  # 1 hour (match token expiry)
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

    # Clear all authentication cookies
    response.delete_cookie("access_token")
    response.delete_cookie("id_token")
    response.delete_cookie("refresh_token")

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
def proxy_image():
    access_token = request.cookies.get("access_token")
    # The actual image URL you want to fetch
    image_url = request.args.get("url", default=None, type=str)
    if not image_url:
        return None

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
    access_token = request.cookies.get("access_token")
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
