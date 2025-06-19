#!/bin/bash
set -e

echo "Cleaning old build..."
rm -rf lambda_build lambda.zip

echo "Creating build dir..."
mkdir lambda_build
cp lambda_function.py lambda_build/

echo "Running Docker to build for x86_64 Amazon Linux 2..."

docker run --platform linux/amd64 --rm -v "$PWD/lambda_build":/var/task -w /var/task python:3.12-slim bash -c "\
  apt-get update && \
  apt-get install -y gcc libffi-dev libssl-dev zip && \
  pip install --upgrade pip && \
  pip install 'PyJWT[crypto]' 'boto3' -t . && \
  zip -r lambda.zip ."

echo "✅ Build complete: lambda.zip is ready for Lambda@Edge"

echo "Deploying Lambda Function & Updating CDN"

cd infra

terraform apply -auto-approve

ROLE_ARN=$(terraform output -raw lambda_iam_role_arn)

ROLE_NAME=$(terraform output -raw lambda_iam_role_name)

ACM_CERT_ARN=$(terraform output -raw acm_cert_arn)

ACM_CERT_DOMAIN=$(terraform output -raw acm_cert_domain)


cd ..

# Inject into zappa_settings.json
jq --arg role_arn "$ROLE_ARN" \
   --arg role_name "$ROLE_NAME" \
   --arg acm_cert_arn "$ACM_CERT_ARN" \
   --arg acm_cert_domain "$ACM_CERT_DOMAIN" \
   '.main.role_arn = $role_arn | .main.role_name = $role_name | .main.certificate_arn = $acm_cert_arn | .main.domain = $acm_cert_domain' \
   zappa_settings.tpl.json > zappa_settings.json


zappa update main || zappa deploy main
