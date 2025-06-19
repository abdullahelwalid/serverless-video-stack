# serverless-video-stack

# Video Streaming Platform

A secure, serverless video streaming platform built with Flask, AWS CloudFront, Lambda@Edge, and AWS Cognito authentication. This platform provides authenticated video streaming with thumbnail generation and a clean web interface.

## Features

- **Secure Authentication**: AWS Cognito integration with JWT token validation
- **Protected Video Streaming**: CloudFront distribution with Lambda@Edge authorization
- **Automatic Thumbnails**: FFmpeg-based thumbnail generation for video previews
- **Responsive Web Interface**: Clean, modern UI for video browsing and playback
- **Serverless Architecture**: Built on AWS Lambda with Zappa framework
- **Infrastructure as Code**: Complete Terraform configuration for AWS resources

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Browser   │───▶│ Flask App    │───▶│   Cognito   │
│             │    │ (Lambda)     │    │ User Pool   │
└─────────────┘    └──────────────┘    └─────────────┘
       │                   │
       │                   ▼
       │            ┌──────────────┐
       │            │      S3      │
       │            │   Bucket     │
       │            └──────────────┘
       │
       ▼
┌─────────────┐    ┌──────────────┐
│ CloudFront  │───▶│ Lambda@Edge  │
│Distribution │    │(Auth Check)  │
└─────────────┘    └──────────────┘
```

## Prerequisites

- **AWS CLI** configured with appropriate permissions
- **Docker** for building Lambda@Edge function
- **Terraform** v1.0+ for infrastructure deployment
- **Python 3.12** for local development
- **FFmpeg** for video processing and thumbnail generation
- **jq** for JSON processing in build scripts

## AWS Permissions Required

Your AWS credentials need the following permissions:

- Lambda (create, update, delete functions)
- CloudFront (create, update distributions)
- S3 (create buckets, upload objects)
- Cognito (create user pools, clients)
- IAM (create roles, policies)
- Secrets Manager (create, read secrets)
- ACM (create, validate certificates)
- Route53 (create DNS records)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd video-streaming-platform
```

### 2. Configure Environment

Create a `.env` file in the root directory:

```env
# Video Upload Configuration
LOCAL_VIDEO_DIR=/path/to/your/videos
BUCKET_NAME=your-s3-bucket-name
AWS_REGION=ap-southeast-1
THUMBNAIL_TIME=00:00:01
VIDEO_SUFFIX=.mp4
THUMB_SUFFIX=.jpg
```

### 3. Deploy Infrastructure

```bash
make deploy
```

This command will:

- Build the Lambda@Edge function using Docker
- Deploy all AWS infrastructure using Terraform
- Deploy the Flask application using Zappa
- Configure CloudFront distribution with custom domain

### 4. Create Cognito Users

After deployment, create users in your Cognito User Pool:

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <your-user-pool-id> \
  --username <username> \
  --temporary-password <temp-password> \
  --message-action SUPPRESS
```

### 5. Upload Videos

Use the provided upload script to process and upload videos:

```bash
python video_upload_pipeline.py
```

This will:

- Apply faststart flag to videos for better streaming
- Generate thumbnails at the specified time
- Upload both videos and thumbnails to S3

## Project Structure

```
video-streaming-platform/
├── app.py                      # Main Flask application
├── config.py                   # Configuration management
├── lambda_function.py          # Lambda@Edge authorization function
├── video_upload_pipeline.py    # Video processing and upload script
├── build.sh                    # Build and deployment script
├── zappa_settings.tpl.json     # Zappa configuration template
├── Makefile                    # Deployment commands
├── infra/                      # Terraform infrastructure code
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── ...
├── templates/                  # Flask HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   └── watch.html
└── static/                     # CSS, JS, and static assets
    ├── css/
    ├── js/
    └── images/
```

## Configuration

### AWS Secrets Manager

The application uses AWS Secrets Manager to store sensitive configuration. should contain:

```json
{
  "BucketName": "your-s3-bucket",
  "CloudfrontDistURL": "your-cloudfront-domain",
  "AWSRegion": "ap-southeast-1",
  "CognitoUserpoolID": "your-user-pool-id",
  "CognitoClientID": "your-client-id",
  "APIKey": "your-secret-key",
  "DomainName": "your-custom-domain"
}
```

### Video Processing Settings

Configure video processing in your `.env` file:

- `THUMBNAIL_TIME`: Time offset for thumbnail generation (default: 00:00:01)
- `VIDEO_SUFFIX`: Video file extension to process (default: .mp4)
- `THUMB_SUFFIX`: Thumbnail file extension (default: .jpg)

## Security Features

### Authentication Flow

1. Users log in with Cognito credentials
2. JWT tokens are stored in secure HTTP-only cookies
3. Lambda@Edge validates tokens for each CloudFront request
4. Expired tokens automatically redirect to login

### Token Validation

- **Access Tokens**: Validated against Cognito public keys
- **JWT Claims**: Verified for issuer, expiration, and audience
- **Resource Authorization**: Tokens tied to specific video resources

### Security Headers

- HTTP-only cookies prevent XSS attacks
- SameSite cookies provide CSRF protection
- Secure cookies in production environments
- CORS headers configured for specific origins

## API Endpoints

### Authentication

- `GET /login` - Login page
- `POST /login` - Process login credentials
- `GET /logout` - Clear session and redirect

### Video Streaming

- `GET /` - Video list (authenticated)
- `GET /watch?file=<key>` - Video player page
- `GET /proxy/image?url=<url>` - Authenticated image proxy

### API

- `GET /api/token` - Get current access token
- `GET /health` - Health check endpoint

## Development

### Local Development

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Set up local environment variables

3. Run the Flask application:

```bash
python app.py
```

### Testing Lambda@Edge Function

The Lambda@Edge function can be tested locally by simulating CloudFront events:

```python
# Test event structure
event = {
    "Records": [{
        "cf": {
            "request": {
                "uri": "/video.mp4",
                "method": "GET",
                "querystring": "token=your-jwt-token",
                "headers": {
                    "origin": [{"value": "https://yourdomain.com"}]
                }
            }
        }
    }]
}
```

## Deployment

### Infrastructure Updates

To update infrastructure only:

```bash
cd infra
terraform plan
terraform apply
```

### Application Updates

To update the Flask application:

```bash
zappa update main
```

### Lambda@Edge Updates

Lambda@Edge functions require rebuilding:

```bash
./build.sh
```

## Monitoring and Troubleshooting

### CloudWatch Logs

- **Flask Application**: `/aws/lambda/video-stream-main`
- **Lambda@Edge**: `/aws/lambda/us-east-1.<function-name>`

### Common Issues

1. **401 Unauthorized**: Check Cognito user pool configuration
2. **403 Forbidden**: Verify Lambda@Edge function deployment
3. **CORS Errors**: Ensure origin is properly configured
4. **Video Won't Load**: Check S3 bucket permissions and CloudFront distribution

### Debug Mode

Enable debug logging by setting environment variables:

```bash
export FLASK_DEBUG=1
export FLASK_ENV=development
```

## Performance Optimization

### Video Optimization

- Videos are processed with `+faststart` flag for better streaming
- CloudFront provides global CDN distribution
- Range requests supported for efficient seeking

### Caching Strategy

- **Static Assets**: Cached at CloudFront edge locations
- **Video Content**: Cached with custom TTL settings
- **Cognito Keys**: Cached in memory for 1 hour

## Cost Optimization

- Lambda functions use minimal memory allocation
- S3 Standard-IA storage class for infrequently accessed videos
- CloudFront caching reduces origin requests
- Cognito pricing scales with active users

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/) web framework
- Deployed using [Zappa](https://github.com/zappa/Zappa) serverless framework
- Infrastructure managed with [Terraform](https://www.terraform.io/)
- Video processing powered by [FFmpeg](https://ffmpeg.org/)
