# Intentionally vulnerable Terraform for testing the DevSecOps AI Agent.
# Issues planted here (do not deploy this in real infrastructure):
#   1. S3 bucket with public-read ACL
#   2. S3 bucket without encryption
#   3. Security group open to 0.0.0.0/0 on port 22 (SSH)
#   4. IAM policy with wildcard "*" actions and resources
#   5. RDS instance without encryption and publicly accessible

resource "aws_s3_bucket" "app_data" {
  bucket = "my-company-app-data"
  acl    = "public-read"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data_unused" {
  # Intentionally NOT referenced/attached anywhere — bucket above has
  # no actual encryption configuration applied to it.
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Security group for web servers"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "overly_permissive" {
  name        = "overly-permissive-policy"
  description = "Grants far too much access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_instance" "main_db" {
  identifier        = "main-database"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "changeme123"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
