terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  # Optionally set region via AWS_REGION env var or override here.
}

locals {
  lambda_function_name = "serverless-cloudwatch-guard"
  sns_topic_name       = "serverless-cloudwatch-guard-alerts"
}

resource "aws_sns_topic" "alerts" {
  name = local.sns_topic_name
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${local.lambda_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid       = "AllowPublishToAlertsTopic"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid    = "AllowBasicLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${local.lambda_function_name}-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_lambda_function" "guard" {
  function_name = local.lambda_function_name
  description   = "Real-time CloudTrail guard for high-risk actions"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  role          = aws_iam_role.lambda_exec.arn

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_inline,
  ]
}

resource "aws_cloudwatch_event_rule" "high_risk_api" {
  name        = "serverless-cloudwatch-guard-high-risk"
  description = "Capture high-risk API calls for real-time alerting"

  event_pattern = jsonencode({
    "source"      : ["aws.iam", "aws.ec2"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail"      : {
      "eventSource" : ["iam.amazonaws.com", "ec2.amazonaws.com"],
      "eventName"   : ["CreateUser", "AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.high_risk_api.name
  target_id = "lambda-${local.lambda_function_name}"
  arn       = aws_lambda_function.guard.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.high_risk_api.arn
}
