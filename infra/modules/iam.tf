resource "aws_iam_role" "lambda_exec" {
  name               = "lambda_exec_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role" "lambda_exec_video_stream" {
  name               = "lambda_exec_role_video_stream"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy_videosteam.json
}

data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_assume_role_policy_videosteam" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "lambda_secrets_access" {
  name = "lambda_secrets_access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          aws_secretsmanager_secret.my_secret.arn,
          "${aws_secretsmanager_secret.my_secret.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_cognito_access" {
  name = "lambda_cognito_access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["cognito-idp:AdminInitiateAuth"]
        Resource = [
          aws_cognito_user_pool.main.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_secrets_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_secrets_access.arn
}


resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


resource "aws_iam_role_policy_attachment" "lambda_secrets_attach_vs" {
  role       = aws_iam_role.lambda_exec_video_stream.name
  policy_arn = aws_iam_policy.lambda_secrets_access.arn
}


resource "aws_iam_role_policy_attachment" "lambda_logs_vs" {
  role       = aws_iam_role.lambda_exec_video_stream.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_cognito_attach" {
  role       = aws_iam_role.lambda_exec_video_stream.name
  policy_arn = aws_iam_policy.lambda_cognito_access.arn
}


