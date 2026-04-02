# Rtr can be imported by specifying the id.
terraform import crowdstrike_rtr_put_file.example 7fb858a949034a0cbca175f660f1e769

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_rtr_put_file.example
  id = "7fb858a949034a0cbca175f660f1e769"
}
