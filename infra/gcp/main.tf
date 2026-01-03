terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" { type = string }
variable "region" { type = string default = "us-central1" }

# NOTE: This is a scaffold only. Fill in:
# - Cloud Run service
# - Cloud SQL + PITR
# - Memorystore Redis
# - Cloud KMS keyring + key
# - GCS bucket with retention
# - Cloud Armor policy via LB

output "next_steps" {
  value = "Fill in Cloud Run/SQL/Redis/KMS/GCS/Armor resources per README.md"
}
