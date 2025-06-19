resource "random_password" "secret_key" {
  length  = 32
  special = true
}


resource "aws_secretsmanager_secret" "my_secret" {
  name = "video-stream/secret-key"
}


locals {
  secrets = {
    APIKey            = random_password.secret_key.result
    AWSRegion         = "ap-southeast-1"
    CognitoUserpoolID = aws_cognito_user_pool.main.id
    CognitoClientID   = aws_cognito_user_pool_client.app.id
    CloudfrontDistURL = aws_cloudfront_distribution.cdn.domain_name
    BucketName        = data.aws_s3_bucket.s3_bucket.bucket
    DomainName        = aws_acm_certificate.api_cert.domain_name
  }
}

resource "aws_secretsmanager_secret_version" "my_secret_version" {
  secret_id     = aws_secretsmanager_secret.my_secret.id
  secret_string = jsonencode(local.secrets)
}
