terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "> 3.1.0"
    }

  }
}

provider "aws" {
  region = "ap-southeast-1"
}


module "kms" {
  source         = "./modules"
  s3_bucket      = var.s3-bucket-name
  route53_domain = var.route53_domain
}
