data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

locals {
  name            = "aws-eks-cluster"
  cluster_version = "1.29"
  region          = "us-east-1"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    project = "aws-eks-cluster"
  }
}

data "aws_eks_cluster_auth" "default" {
  name = module.eks.cluster_name
}

# provider "kubernetes" {
#   host                   = module.eks.cluster_endpoint
#   cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
#   token                  = data.aws_eks_cluster_auth.default.token
# }

module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name                    = local.name
  cluster_version                 = local.cluster_version
  cluster_endpoint_public_access  = true # This is necessary to access the cluster from outside the VPC, like github or locally
  cluster_endpoint_private_access = true

  # IPV6
  cluster_ip_family = "ipv4"
  # create_cni_ipv6_iam_policy = true

  enable_cluster_creator_admin_permissions = true

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent    = true
      before_compute = true
      configuration_values = jsonencode({
        env = {
          # Reference docs https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
          # This will deliver a /28 prefix for each secondary ipv4 in the eni
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets # where node groups run
  control_plane_subnet_ids = module.vpc.intra_subnets   # where ENIs from control plane are deployed

  eks_managed_node_group_defaults = {
    instance_types = ["t3.medium"]
  }

  eks_managed_node_groups = {
    bottlerocket = {
      # By default, the module creates a launch template to ensure tags are propagated to instances, etc.,
      # so we need to disable it to use the default template provided by the AWS EKS managed node group service
      use_custom_launch_template = false

      desired_size = 1
      max_size     = 2
      ami_type     = "BOTTLEROCKET_x86_64"

      create_iam_role = true
      iam_role_name   = "aws-eks-cluster-instance-role"
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  fargate_profiles = {
    fargate_profile = {
      selectors = [
        {
          namespace = "fargate"
        },
        {
          namespace = "karpenter"
        }
      ]
    }
  }
  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]      ## 10.0.0.0/20, 10.0.16.0/20, 10.0.32.0/20
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)] ## 10.0.48.0/24, 10.0.49.0/24, 10.0.50.0/24
  intra_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 52)] ## Subnet with no routing to the internet

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_ipv6            = false
  create_egress_only_igw = true

  # public_subnet_ipv6_prefixes                    = [0, 1, 2]
  # public_subnet_assign_ipv6_address_on_creation  = true
  # private_subnet_ipv6_prefixes                   = [3, 4, 5]
  # private_subnet_assign_ipv6_address_on_creation = true
  # intra_subnet_ipv6_prefixes                     = [6, 7, 8]
  # intra_subnet_assign_ipv6_address_on_creation   = true

  # https://docs.aws.amazon.com/eks/latest/userguide/network-load-balancing.html#subnet-tagging-for-load-balancers
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}

module "ebs_kms_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 2.1"

  description = "Customer managed key to encrypt EKS managed node group volumes"

  # Policy
  key_administrators = [
    data.aws_caller_identity.current.arn
  ]

  key_service_roles_for_autoscaling = [
    # required for the ASG to manage encrypted volumes for nodes
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
    # required for the cluster / persistentvolume-controller to create encrypted PVCs
    module.eks.cluster_iam_role_arn,
  ]

  # Aliases
  aliases = ["eks/${local.name}/ebs"]

  tags = local.tags
}

module "key_pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "~> 2.0"

  key_name_prefix    = local.name
  create_private_key = true

  tags = local.tags
}

resource "aws_security_group" "remote_access" {
  name_prefix = "${local.name}-remote-access"
  description = "Allow remote SSH access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-remote" })
}

