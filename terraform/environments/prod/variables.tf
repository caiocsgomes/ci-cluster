## Project wide variables
variable "project_name" {
  default = "ci-cluster"
}
variable "region" {
  default = "us-east-1"
}
variable "profile" {
  default = "default"
}
variable "availability_zones" {
  type = list(string)
}

## VPC variables
variable "vpc_cidr" {
  type = string
}
variable "private_subnets" {
  type = list(string)
}
variable "public_subnets" {
  type = list(string)
}
variable "enable_nat_gateway" {
  type = bool
}
variable "enable_vpn_gateway" {
  type = bool
}
variable "vpc_tags" {
  type = map(string)
}

## EKS variables

variable "instance_types" {
  type    = list(string)
  default = ["t2.medium"]
}
variable "disk_size" {
  type    = number
  default = 50
}
variable "eks_tags" {
  type = map(string)
  default = {
    Name = "aws-eks-cluster"
  }
}
