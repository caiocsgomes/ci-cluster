# https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html
module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc"

  name = var.project_name
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway = var.enable_nat_gateway
  enable_vpn_gateway = var.enable_vpn_gateway

  tags = var.vpc_tags
}
