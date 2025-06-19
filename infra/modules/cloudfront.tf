

data "aws_s3_bucket" "s3_bucket" {
  bucket = var.s3_bucket
}




resource "aws_cloudfront_origin_access_control" "origin_ac" {
  name                              = "video-ac"
  description                       = "video-ac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals {
  s3_origin_id = "video-stream"
}




# Custom response headers policy for CORS
resource "aws_cloudfront_response_headers_policy" "cors_policy" {
  name    = "cors-policy"
  comment = "CORS policy for video streaming with cookie authentication"

  cors_config {
    access_control_allow_credentials = true

    access_control_allow_headers {
      items = [
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "Range",
        "Cookie",
        "X-Requested-With"
      ]
    }

    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }

    access_control_allow_origins {
      items = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "cdn.${var.route53_domain}"
      ]
    }

    access_control_expose_headers {
      items = [
        "Accept-Ranges",
        "Content-Range",
        "Content-Length",
        "Content-Type",
        "ETag",
        "Last-Modified"
      ]
    }

    access_control_max_age_sec = 3600
    origin_override            = true
  }

  # Security headers
  security_headers_config {
    content_security_policy {
      content_security_policy = "default-src 'self'; media-src 'self' data: blob:; style-src 'self' 'unsafe-inline'"
      override                = false
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
  }
}

# Cache policy for video content with proper headers
resource "aws_cloudfront_cache_policy" "video_cache_policy" {
  name        = "video-cache-policy"
  comment     = "Cache policy optimized for video streaming with CORS"
  default_ttl = 86400    # 1 day
  max_ttl     = 31536000 # 1 year
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    headers_config {
      header_behavior = "whitelist"
      headers {
        items = [
          "Range",
          "Origin",
          "Access-Control-Request-Method",
          "Access-Control-Request-Headers"
        ]
      }
    }

    query_strings_config {
      query_string_behavior = "none"
    }

    cookies_config {
      cookie_behavior = "none" # Don't cache based on cookies for video content
    }
  }
}

# Origin request policy for S3 with proper headers
resource "aws_cloudfront_origin_request_policy" "s3_origin_policy" {
  name    = "s3-origin-policy"
  comment = "Origin request policy for S3 with CORS headers"

  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "Range",
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
      ]
    }
  }

  query_strings_config {
    query_string_behavior = "none"
  }

  cookies_config {
    cookie_behavior = "all" # Forward all cookies for authentication
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Video CDN Distribution with CORS"

  origin {
    domain_name              = data.aws_s3_bucket.s3_bucket.bucket_regional_domain_name
    origin_id                = local.s3_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.origin_ac.id

    # Add custom headers for CORS
    custom_header {
      name  = "Access-Control-Allow-Origin"
      value = "*"
    }
  }

  # Default cache behavior for video files
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"] # Added OPTIONS for CORS
    cached_methods         = ["GET", "HEAD", "OPTIONS"] # Added OPTIONS for CORS
    target_origin_id       = local.s3_origin_id
    viewer_protocol_policy = "redirect-to-https"

    # Use custom policies for better CORS and video streaming
    cache_policy_id            = aws_cloudfront_cache_policy.video_cache_policy.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.s3_origin_policy.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors_policy.id

    # Compress content for better performance
    compress = true

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.jwt_validator.qualified_arn
      include_body = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }


  tags = {
    Name = "video-cdn"
  }
}
