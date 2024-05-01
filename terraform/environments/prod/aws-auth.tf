module "eks" {
  source  = "terraform-aws-modules/eks/aws//modules/aws-auth"
  version = "~> 20.8.5"

  manage_aws_auth_configmap = true

  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/caio"
      username = "caio"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      username = "root"
      groups   = ["system:masters"]
    },
  ]

  aws_auth_accounts = [
    "${data.aws_caller_identity.current.account_id}"
  ]
}
