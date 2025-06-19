variable "s3-bucket-name" {
  type     = string
  nullable = false
  default  = "videos-actioncamera-random"
}

variable "route53_domain" {
  type     = string
  nullable = false
  default  = "abdullahelwalid.com"
}
