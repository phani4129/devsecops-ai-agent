# Remediated version of test_configs/vulnerable/main.tf
# Shows the corrected configuration after applying the agent's fixes.

resource "aws_s3_bucket" "app_data" {
  bucket = "my-company-app-data"
}

resource "aws_s3_bucket_acl" "app_data_acl" {
  bucket = aws_s3_bucket.app_data.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data_encryption" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Security group for web servers"

  ingress {
    description = "SSH from corporate VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "scoped_policy" {
  name        = "scoped-s3-read-policy"
  description = "Grants least-privilege read access to one bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.app_data.arn,
          "${aws_s3_bucket.app_data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_db_instance" "main_db" {
  identifier          = "main-database"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password # pulled from a secrets manager / tfvars, never hardcoded
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = false
}
