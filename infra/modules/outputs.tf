output "lambda_iam_role_arn" {
  value = aws_iam_role.lambda_exec_video_stream.arn
}

output "lambda_iam_role_name" {
  value = aws_iam_role.lambda_exec_video_stream.name
}

output "acm_cert_arn" {
  value = aws_acm_certificate.api_cert.arn
}

output "acm_cert_domain" {
  value = aws_acm_certificate.api_cert.domain_name
}
