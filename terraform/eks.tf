module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name               = local.name
  kubernetes_version = local.cluster_version

  # EKS Addons
  addons = {
    coredns = {}
    eks-pod-identity-agent = {
      before_compute = true
    }
    kube-proxy = {}
    vpc-cni = {
      before_compute = true
    }
  }

  endpoint_public_access                   = true
  enable_cluster_creator_admin_permissions = true


  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    al2023 = {
      # Starting on 1.30, AL2023 is the default AMI type for EKS managed node groups
      instance_types = ["t3.medium"]
      ami_type       = "AL2023_x86_64_STANDARD"

      min_size = 1
      max_size = 2
      # This value is ignored after the initial creation
      # https://github.com/bryantbiggs/eks-desired-size-hack
      desired_size = 2

      # This is not required - demonstrates how to pass additional configuration to nodeadm
      # Ref https://awslabs.github.io/amazon-eks-ami/nodeadm/doc/api/
      cloudinit_pre_nodeadm = [
        {
          content_type = "application/node.eks.aws"
          content      = <<-EOT
            ---
            apiVersion: node.eks.aws/v1alpha1
            kind: NodeConfig
            spec:
              kubelet:
                config:
                  shutdownGracePeriod: 30s
          EOT
        }
      ]
    }
  }

  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################
#
# module "ebs_kms_key" {
#   source  = "terraform-aws-modules/kms/aws"
#   version = "~> 2.1"
#
#   description = "Customer managed key to encrypt EKS managed node group volumes"
#
#   # Policy
#   key_administrators = [
#     data.aws_caller_identity.current.arn
#   ]
#
#   key_service_roles_for_autoscaling = [
#     # required for the ASG to manage encrypted volumes for nodes
#     "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
#     # required for the cluster / persistentvolume-controller to create encrypted PVCs
#     module.eks.cluster_iam_role_arn,
#   ]
#
#   # Aliases
#   aliases = ["eks/${local.name}/ebs"]
#
#   tags = local.tags
# }
#
# module "key_pair" {
#   source  = "terraform-aws-modules/key-pair/aws"
#   version = "~> 2.0"
#
#   key_name_prefix    = local.name
#   create_private_key = true
#
#   tags = local.tags
# }
#
# resource "aws_security_group" "remote_access" {
#   name_prefix = "${local.name}-remote-access"
#   description = "Allow remote SSH access"
#   vpc_id      = module.vpc.vpc_id
#
#   ingress {
#     description = "SSH access"
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["10.0.0.0/8"]
#   }
#
#   egress {
#     from_port        = 0
#     to_port          = 0
#     protocol         = "-1"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }
#
#   tags = merge(local.tags, { Name = "${local.name}-remote" })
# }
#
