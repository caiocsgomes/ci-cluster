resource "aws_iam_policy" "load_balancer_controller_iam_policy" {
  name        = "AWSLoadBalancerControllerIAMPolicy"
  path        = "/"
  description = "IAM policy for the AWS Load Balancer Controller"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "iam:CreateServiceLinkedRole"
          ],
          "Resource" : "*",
          "Condition" : {
            "StringEquals" : {
              "iam:AWSServiceName" : "elasticloadbalancing.amazonaws.com"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:DescribeAccountAttributes",
            "ec2:DescribeAddresses",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeInternetGateways",
            "ec2:DescribeVpcs",
            "ec2:DescribeVpcPeeringConnections",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeInstances",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeTags",
            "ec2:GetCoipPoolUsage",
            "ec2:DescribeCoipPools",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeListenerCertificates",
            "elasticloadbalancing:DescribeSSLPolicies",
            "elasticloadbalancing:DescribeRules",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetGroupAttributes",
            "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:DescribeTags",
            "elasticloadbalancing:DescribeTrustStores"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "cognito-idp:DescribeUserPoolClient",
            "acm:ListCertificates",
            "acm:DescribeCertificate",
            "iam:ListServerCertificates",
            "iam:GetServerCertificate",
            "waf-regional:GetWebACL",
            "waf-regional:GetWebACLForResource",
            "waf-regional:AssociateWebACL",
            "waf-regional:DisassociateWebACL",
            "wafv2:GetWebACL",
            "wafv2:GetWebACLForResource",
            "wafv2:AssociateWebACL",
            "wafv2:DisassociateWebACL",
            "shield:GetSubscriptionState",
            "shield:DescribeProtection",
            "shield:CreateProtection",
            "shield:DeleteProtection"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:CreateSecurityGroup"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:CreateTags"
          ],
          "Resource" : "arn:aws:ec2:*:*:security-group/*",
          "Condition" : {
            "StringEquals" : {
              "ec2:CreateAction" : "CreateSecurityGroup"
            },
            "Null" : {
              "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:CreateTags",
            "ec2:DeleteTags"
          ],
          "Resource" : "arn:aws:ec2:*:*:security-group/*",
          "Condition" : {
            "Null" : {
              "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
              "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:DeleteSecurityGroup"
          ],
          "Resource" : "*",
          "Condition" : {
            "Null" : {
              "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:CreateTargetGroup"
          ],
          "Resource" : "*",
          "Condition" : {
            "Null" : {
              "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:DeleteListener",
            "elasticloadbalancing:CreateRule",
            "elasticloadbalancing:DeleteRule"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:RemoveTags"
          ],
          "Resource" : [
            "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
            "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
            "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
          ],
          "Condition" : {
            "Null" : {
              "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
              "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:RemoveTags"
          ],
          "Resource" : [
            "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
            "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
            "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
            "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            "elasticloadbalancing:SetIpAddressType",
            "elasticloadbalancing:SetSecurityGroups",
            "elasticloadbalancing:SetSubnets",
            "elasticloadbalancing:DeleteLoadBalancer",
            "elasticloadbalancing:ModifyTargetGroup",
            "elasticloadbalancing:ModifyTargetGroupAttributes",
            "elasticloadbalancing:DeleteTargetGroup"
          ],
          "Resource" : "*",
          "Condition" : {
            "Null" : {
              "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:AddTags"
          ],
          "Resource" : [
            "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
            "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
            "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
          ],
          "Condition" : {
            "StringEquals" : {
              "elasticloadbalancing:CreateAction" : [
                "CreateTargetGroup",
                "CreateLoadBalancer"
              ]
            },
            "Null" : {
              "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
            }
          }
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:DeregisterTargets"
          ],
          "Resource" : "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:SetWebAcl",
            "elasticloadbalancing:ModifyListener",
            "elasticloadbalancing:AddListenerCertificates",
            "elasticloadbalancing:RemoveListenerCertificates",
            "elasticloadbalancing:ModifyRule"
          ],
          "Resource" : "*"
        }
      ]
    }
  )
}

module "iam_eks_role_load_balancer_controller" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  role_name = "aws-load-balancer-controller"

  role_policy_arns = {
    policy = aws_iam_policy.load_balancer_controller_iam_policy.arn
  }

  oidc_providers = {
    one = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["aws-load-balancer-controller:aws-load-balancer-controller"]
    }
  }
}

## External secrets IAM Role
resource "aws_iam_policy" "external_secrets_iam_policy" {
  name        = "ExternalSecretsIAMPolicy"
  path        = "/"
  description = "IAM policy for the External Secrets Controller"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "secretsmanager:GetSecretValue",
          ],
          "Resource" : "*",
        },
      ]
    }
  )
}

module "iam_eks_role_external_secrets_controller" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  role_name = "external-secrets-controller"

  role_policy_arns = {
    policy = aws_iam_policy.external_secrets_iam_policy.arn
  }

  oidc_providers = {
    one = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:external-secrets-aws-irsa"]
    }
  }
}

## https://karpenter.sh/docs/reference/cloudformation/#node-authorization
data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_eks_role_karpenter_node_role" {
  name                = "iam_eks_role_karpenter_node_role"
  assume_role_policy  = data.aws_iam_policy_document.instance_assume_role_policy.json # (not shown)
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy", "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

## https://karpenter.sh/docs/reference/cloudformation/#controller-authorization
resource "aws_iam_policy" "karpenter_controller_policy" {
  name        = "KarpenterControllerPolicy"
  path        = "/"
  description = "IAM policy for the Karpenter Controller"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "secretsmanager:GetSecretValue",
          ],
          "Resource" : "*",
        },
        {
          "Sid" : "AllowScopedEC2InstanceAccessActions",
          "Effect" : "Allow",
          "Resource" : [
            "arn:aws:ec2:*::image/*",
            "arn:aws:ec2:*::snapshot/*",
            "arn:aws:ec2:*:*:security-group/*",
            "arn:aws:ec2:*:*:subnet/*"
          ],
          "Action" : [
            "ec2:RunInstances",
            "ec2:CreateFleet"
          ]
        },
        {
          "Sid" : "AllowScopedEC2LaunchTemplateAccessActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:ec2:*:*:launch-template/*",
          "Action" : [
            "ec2:RunInstances",
            "ec2:CreateFleet"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:ResourceTag/kubernetes.io/cluster/${var.project_name}" : "owned"
            },
            "StringLike" : {
              "aws:ResourceTag/karpenter.sh/nodepool" : "*"
            }
          }
        },
        {
          "Sid" : "AllowScopedEC2InstanceActionsWithTags",
          "Effect" : "Allow",
          "Resource" : [
            "arn:aws:ec2:*:*:fleet/*",
            "arn:aws:ec2:*:*:instance/*",
            "arn:aws:ec2:*:*:volume/*",
            "arn:aws:ec2:*:*:network-interface/*",
            "arn:aws:ec2:*:*:launch-template/*",
            "arn:aws:ec2:*:*:spot-instances-request/*"
          ],
          "Action" : [
            "ec2:RunInstances",
            "ec2:CreateFleet",
            "ec2:CreateLaunchTemplate"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:RequestTag/kubernetes.io/cluster/${var.project_name}" : "owned"
              "aws:RequestTag/eks:eks-cluster-name" : "${var.project_name}"
            },
            "StringLike" : {
              "aws:RequestTag/karpenter.sh/nodepool" : "*"
            }
          }
        },
        {
          "Sid" : "AllowScopedResourceCreationTagging",
          "Effect" : "Allow",
          "Resource" : [
            "arn:aws:ec2:*:*:fleet/*",
            "arn:aws:ec2:*:*:instance/*",
            "arn:aws:ec2:*:*:volume/*",
            "arn:aws:ec2:*:*:network-interface/*",
            "arn:aws:ec2:*:*:launch-template/*",
            "arn:aws:ec2:*:*:spot-instances-request/*"
          ],
          "Action" : "ec2:CreateTags",
          "Condition" : {
            "StringEquals" : {
              "aws:RequestTag/kubernetes.io/cluster/${var.project_name}" : "owned",
              "aws:RequestTag/eks:eks-cluster-name" : "${var.project_name}"
              "ec2:CreateAction" : [
                "RunInstances",
                "CreateFleet",
                "CreateLaunchTemplate"
              ]
            },
            "StringLike" : {
              "aws:RequestTag/karpenter.sh/nodepool" : "*"
            }
          }
        },
        {
          "Sid" : "AllowScopedResourceTagging",
          "Effect" : "Allow",
          "Resource" : "arn:aws:ec2:*:*:instance/*",
          "Action" : "ec2:CreateTags",
          "Condition" : {
            "StringEquals" : {
              "aws:ResourceTag/kubernetes.io/cluster/${var.project_name}" : "owned"
            },
            "StringLike" : {
              "aws:ResourceTag/karpenter.sh/nodepool" : "*"
            },
            "StringEqualsIfExists" : {
              "aws:RequestTag/eks:eks-cluster-name" : "${var.project_name}"
            },
            "ForAllValues:StringEquals" : {
              "aws:TagKeys" : [
                "eks:eks-cluster-name",
                "karpenter.sh/nodeclaim",
                "Name"
              ]
            }
          }
        },
        {
          "Sid" : "AllowScopedDeletion",
          "Effect" : "Allow",
          "Resource" : [
            "arn:aws:ec2:*:*:instance/*",
            "arn:aws:ec2:*:*:launch-template/*"
          ],
          "Action" : [
            "ec2:TerminateInstances",
            "ec2:DeleteLaunchTemplate"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:ResourceTag/kubernetes.io/cluster/${var.project_name}" : "owned"
            },
            "StringLike" : {
              "aws:ResourceTag/karpenter.sh/nodepool" : "*"
            }
          }
        },
        {
          "Sid" : "AllowRegionalReadActions",
          "Effect" : "Allow",
          "Resource" : "*",
          "Action" : [
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeImages",
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceTypeOfferings",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeLaunchTemplates",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSpotPriceHistory",
            "ec2:DescribeSubnets"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:RequestedRegion" : "*"
            }
          }
        },
        {
          "Sid" : "AllowSSMReadActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:ssm:*::parameter/aws/service/*",
          "Action" : "ssm:GetParametersByPath"
        },
        {
          "Sid" : "AllowPricingReadActions",
          "Effect" : "Allow",
          "Resource" : "*",
          "Action" : "pricing:GetProducts"
        },
        {
          "Sid" : "AllowPassingInstanceRole",
          "Effect" : "Allow",
          "Resource" : "${aws_iam_role.iam_eks_role_karpenter_node_role.arn}",
          "Action" : "iam:PassRole",
          "Condition" : {
            "StringEquals" : {
              "iam:PassedToService" : "ec2.amazonaws.com"
            }
          }
        },
        {
          "Sid" : "AllowScopedInstanceProfileCreationActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
          "Action" : [
            "iam:CreateInstanceProfile"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:RequestTag/kubernetes.io/cluster/${var.project_name}" : "owned",
              "aws:RequestTag/eks:eks-cluster-name" : "${var.project_name}",
              "aws:RequestTag/topology.kubernetes.io/region" : "*"
            },
            "StringLike" : {
              "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass" : "*"
            }
          }
        },
        {
          "Sid" : "AllowScopedInstanceProfileTagActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
          "Action" : [
            "iam:TagInstanceProfile"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:ResourceTag/kubernetes.io/cluster/${var.project_name}" : "owned",
              "aws:ResourceTag/topology.kubernetes.io/region" : "*",
              "aws:RequestTag/kubernetes.io/cluster/${var.project_name}" : "owned",
              "aws:RequestTag/eks:eks-cluster-name" : "${var.project_name}",
              "aws:RequestTag/topology.kubernetes.io/region" : "*"
            },
            "StringLike" : {
              "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass" : "*",
              "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass" : "*"
            }
          }
        },
        {
          "Sid" : "AllowScopedInstanceProfileActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
          "Action" : [
            "iam:AddRoleToInstanceProfile",
            "iam:RemoveRoleFromInstanceProfile",
            "iam:DeleteInstanceProfile"
          ],
          "Condition" : {
            "StringEquals" : {
              "aws:ResourceTag/kubernetes.io/cluster/${var.project_name}" : "owned",
              "aws:ResourceTag/topology.kubernetes.io/region" : "*"
            },
            "StringLike" : {
              "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass" : "*"
            }
          }
        },
        {
          "Sid" : "AllowInstanceProfileReadActions",
          "Effect" : "Allow",
          "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
          "Action" : "iam:GetInstanceProfile"
        },
        {
          "Sid" : "AllowAPIServerEndpointDiscovery",
          "Effect" : "Allow",
          "Resource" : "arn:aws:eks:*:${data.aws_caller_identity.current.account_id}:cluster/${var.project_name}",
          "Action" : "eks:DescribeCluster"
        }
      ]
    }
  )
}

module "iam_eks_role_karpenter_controller" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  role_name = "karpenter-controller"

  role_policy_arns = {
    policy = aws_iam_policy.karpenter_controller_policy.arn
  }

  oidc_providers = {
    one = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["karpenter:karpenter-controller-irsa"]
    }
  }
}
