terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20.0"
    }
  }

  backend "s3" {
    bucket         = "aws-eks-cluster-tf-backend-20240417210225955700000001"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "aws-eks-cluster-tf-backend"
    encrypt        = true
  }
}
