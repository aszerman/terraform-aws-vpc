locals {
  javans_source_cidrs = [
    "10.88.0.0/16",      # jvns-vpn
    "52.67.134.70/32",   # jvns-nat01
    "52.67.71.87/32",    # monitoreo-viejo
    "52.67.202.45/32",   # jvns-fw01
    "34.229.35.53/32"    # jvns-fw02
  ]
}

resource "aws_security_group" "javans_custom" {
  name        = "SG_JavaNS"
  description = "Allow custom access for JavaNS"
  vpc_id      = local.vpc_id

  # Inbound rules
  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow SSH from JavaNS sources"
  }

  # RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow RDP from JavaNS sources"
  }

  # WinRM HTTP
  ingress {
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow WinRM HTTP from JavaNS sources"
  }

  # WinRM HTTPS
  ingress {
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow WinRM HTTPS from JavaNS sources"
  }

  # ICMP
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow ICMP from JavaNS sources"
  }

  # Zabbix Agent
  ingress {
    from_port   = 10050
    to_port     = 10050
    protocol    = "tcp"
    cidr_blocks = local.javans_source_cidrs
    description = "Allow Zabbix Agent from JavaNS sources"
  }

  # Egress rule
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(
    var.tags,
    {
      Name = "SG_JavaNS"
    }
  )
}

resource "aws_security_group" "javans_all" {
  name        = "SG_JavaNS_ALL"
  description = "Allow all traffic from SG_JavaNS"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.javans_custom.id]
    description     = "Allow all traffic from SG_JavaNS"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(
    var.tags,
    {
      Name = "SG_JavaNS_ALL"
    }
  )
}

# # SSM private endpoints and settings
# data "aws_region" "current" {}

# resource "aws_security_group" "ssm_endpoints" {
#   name        = "SG_SSM_Endpoints"
#   description = "Allow VPC traffic to SSM endpoints"
#   vpc_id      = local.vpc_id

#   ingress {
#     from_port   = 443
#     to_port     = 443
#     protocol    = "tcp"
#     cidr_blocks = [var.cidr]
#     description = "Allow HTTPS from VPC"
#   }

#   egress {
#     from_port        = 0
#     to_port          = 0
#     protocol         = "-1"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   tags = merge(
#     var.tags,
#     {
#       Name = "SG_SSM_Endpoints"
#     }
#   )
# }

# resource "aws_vpc_endpoint" "ssm" {
#   vpc_id              = local.vpc_id
#   service_name        = "com.amazonaws.${data.aws_region.current.name}.ssm"
#   vpc_endpoint_type   = "Interface"
#   subnet_ids          = var.private_subnets
#   security_group_ids  = [aws_security_group.ssm_endpoints.id]
#   private_dns_enabled = true
#   tags = merge(var.tags, { Name = "SSM Endpoint" })
# }

# resource "aws_vpc_endpoint" "ssmmessages" {
#   vpc_id              = local.vpc_id
#   service_name        = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
#   vpc_endpoint_type   = "Interface"
#   subnet_ids          = var.private_subnets
#   security_group_ids  = [aws_security_group.ssm_endpoints.id]
#   private_dns_enabled = true
#   tags = merge(var.tags, { Name = "SSM Messages Endpoint" })
# }

# resource "aws_vpc_endpoint" "ec2messages" {
#   vpc_id              = local.vpc_id
#   service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
#   vpc_endpoint_type   = "Interface"
#   subnet_ids          = var.private_subnets
#   security_group_ids  = [aws_security_group.ssm_endpoints.id]
#   private_dns_enabled = true
#   tags = merge(var.tags, { Name = "EC2 Messages Endpoint" })
# }

# resource "aws_vpc_endpoint" "logs" {
#   vpc_id              = local.vpc_id
#   service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
#   vpc_endpoint_type   = "Interface"
#   subnet_ids          = var.private_subnets
#   security_group_ids  = [aws_security_group.ssm_endpoints.id]
#   private_dns_enabled = true
#   tags = merge(var.tags, { Name = "CloudWatch Logs Endpoint" })
# }

# resource "aws_vpc_endpoint" "kms" {
#   vpc_id              = local.vpc_id
#   service_name        = "com.amazonaws.${data.aws_region.current.name}.kms"
#   vpc_endpoint_type   = "Interface"
#   subnet_ids          = var.private_subnets
#   security_group_ids  = [aws_security_group.ssm_endpoints.id]
#   private_dns_enabled = true
#   tags = merge(var.tags, { Name = "KMS Endpoint" })
# }

# resource "aws_vpc_endpoint" "s3" {
#   vpc_id            = local.vpc_id
#   service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
#   vpc_endpoint_type = "Gateway"
#   route_table_ids   = local.private_route_table_ids
#   tags = merge(var.tags, { Name = "S3 Gateway Endpoint" })
# } 


# IAM Role for Data Lifecycle Manager
resource "aws_iam_role" "dlm_lifecycle_role" {
  name = "dlm-lifecycle-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "dlm.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for Data Lifecycle Manager
resource "aws_iam_role_policy" "dlm_lifecycle_policy" {
  name = "dlm-lifecycle-policy"
  role = aws_iam_role.dlm_lifecycle_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CreateSnapshots",
          "ec2:DeleteSnapshot",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "arn:aws:ec2::*:snapshot/*"
      }
    ]
  })
}

# Data Lifecycle Manager - SnapHourly
resource "aws_dlm_lifecycle_policy" "snap_hourly" {
  description        = "SnapHourly_4h_12ret"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "SnapHourly"

      create_rule {
        interval      = 4
        interval_unit = "HOURS"
        times         = ["00:00"]
      }

      retain_rule {
        count = 12
      }

      tags_to_add = {
        "SnapHourly" = "True"
        "CreatedBy"  = "DLM"
      }

      copy_tags = true
    }

    target_tags = {
      "SnapHourly" = "True"
    }
  }

  tags = merge(var.tags, { Name = "SnapHourly-Lifecycle-Policy" })
}

# Data Lifecycle Manager - SnapDaily
resource "aws_dlm_lifecycle_policy" "snap_daily" {
  description        = "SnapDaily_24h_14ret"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "SnapDaily"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["02:00"]
      }

      retain_rule {
        count = 14
      }

      tags_to_add = {
        "SnapDaily" = "True"
        "CreatedBy" = "DLM"
      }

      copy_tags = true
    }

    target_tags = {
      "SnapDaily" = "True"
    }
  }

  tags = merge(var.tags, { Name = "SnapDaily-Lifecycle-Policy" })
}

# Data Lifecycle Manager - SnapWeekly
resource "aws_dlm_lifecycle_policy" "snap_weekly" {
  description        = "SnapWeekly_8w_ret"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "SnapWeekly"

      create_rule {
        cron_expression = "0 3 ? * SUN *"
      }

      retain_rule {
        count = 8
      }

      tags_to_add = {
        "SnapWeekly" = "True"
        "CreatedBy"  = "DLM"
      }

      copy_tags = true
    }

    target_tags = {
      "SnapWeekly" = "True"
    }
  }

  tags = merge(var.tags, { Name = "SnapWeekly-Lifecycle-Policy" })
}

# Data Lifecycle Manager - SnapMonthly
resource "aws_dlm_lifecycle_policy" "snap_monthly" {
  description        = "SnapMonthly_6m_ret"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "SnapMonthly"

      create_rule {
        cron_expression = "0 4 1 * ? *"
      }

      retain_rule {
        count = 6
      }

      tags_to_add = {
        "SnapMonthly" = "True"
        "CreatedBy"   = "DLM"
      }

      copy_tags = true
    }

    target_tags = {
      "SnapMonthly" = "True"
    }
  }

  tags = merge(var.tags, { Name = "SnapMonthly-Lifecycle-Policy" })
}

# Data Lifecycle Manager - SnapYearly
resource "aws_dlm_lifecycle_policy" "snap_yearly" {
  description        = "SnapYearly_3y_ret"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["INSTANCE"]

    schedule {
      name = "SnapYearly"

      create_rule {
        cron_expression = "0 5 1 1 ? *"
      }

      retain_rule {
        count = 3
      }

      tags_to_add = {
        "SnapYearly" = "True"
        "CreatedBy"  = "DLM"
      }

      copy_tags = true
    }

    target_tags = {
      "SnapYearly" = "True"
    }
  }

  tags = merge(var.tags, { Name = "SnapYearly-Lifecycle-Policy" })
}

