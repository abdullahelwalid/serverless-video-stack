output "lambda_iam_role_arn" {
  value = module.kms.lambda_iam_role_arn
}

output "lambda_iam_role_name" {
  value = module.kms.lambda_iam_role_name
}

output "acm_cert_arn" {
  value = module.kms.acm_cert_arn
}

output "acm_cert_domain" {
  value = module.kms.acm_cert_domain
}
