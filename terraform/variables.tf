variable "project_name" {
  default = "k8s-playground"
}
variable "vpc_cidr" {
  type = string
}
variable "availability_zones" {
  type = list(string)
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
