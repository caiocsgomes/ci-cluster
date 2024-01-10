terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20.0"
    }
  }

  backend "s3" {
    bucket         = "k8s-github-actions-tf-backend-20240110055046188100000001"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "k8s-github-actions-tf-backend"
    encrypt        = true
  }
}
