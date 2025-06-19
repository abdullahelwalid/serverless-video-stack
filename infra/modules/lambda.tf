provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}



resource "aws_lambda_function" "jwt_validator" {
  provider         = aws.us_east_1
  filename         = "../lambda_build/lambda.zip"
  function_name    = "jwtValidator"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = filebase64sha256("../lambda_build/lambda.zip")
  publish          = true
  architectures    = ["x86_64"]
}


