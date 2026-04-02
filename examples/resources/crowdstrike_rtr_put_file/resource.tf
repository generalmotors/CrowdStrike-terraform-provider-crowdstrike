terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}


resource "crowdstrike_rtr_put_file" "example" {
  name        = "file.exe"
  description = "File is managed via Terraform"
  file_path   = "./bin/file.exe"
}

output "example_file" {
  value = crowdstrike_rtr_put_file.example
}
