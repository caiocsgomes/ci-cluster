resource "aws_iam_policy" "alb_controller" {
  name   = "AWSLoadBalancerControllerIAMPolicy"
  policy = file("${path.module}/files/alb_controller_iam_policy.json")
}

data "aws_caller_identity" "current" {}

locals {
  default_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEksPodsToAssume"
      Effect = "Allow"
      Principal = {
        Service = "pods.eks.amazonaws.com"
      }
      Action = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role" "alb_controller" {
  name               = "AmazonEKSLoadBalancerControllerRole"
  assume_role_policy = local.default_trust
}

resource "aws_iam_role_policy_attachment" "alb_controller_attach" {
  role       = aws_iam_role.alb_controller.name
  policy_arn = aws_iam_policy.alb_controller.arn
}

resource "aws_eks_pod_identity_association" "alb_controller" {
  depends_on      = [module.eks]
  cluster_name    = var.project_name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.alb_controller.arn
}
