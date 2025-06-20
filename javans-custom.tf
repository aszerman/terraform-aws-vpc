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