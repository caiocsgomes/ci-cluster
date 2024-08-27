# ci-cluster

This is an EKS cluster for Continuous Integration build jobs. This is meant to be a production grade cluster to test solutions related to building applications and also study.

## Specifications

### Architecture
- CoreDNS and Karpenter running in Fargate, this is meant to isolate these resources which are critical and also isolate Karpenter from the resources it creates - DONE
- Karpenter provisioning all instances - DONE
- All k8s workloads with resource profiles and dependencies well defined in manifests/charts

### Pipeline
- Terraform deploying all resources from a workflow - DONE
- ArgoCD being deployed from a workflow and taking over from there and deploying all other charts and manifests following the app of apps pattern - DONE
- Workflow creating all DNS config necessary to have apps accessible through the internet
- ArgoCD needs to deploy in waves, basic drivers and controllers -> o11y -> remaining resouces - DONE
- Workflow destroying all resources (terraform and argocd managed) at night

### Github Actions Self Hosted Runners
- Caching for images enables in runners using docker in docker
- Runners of different sizes and specs

### Observability
- Grafana, Prometheus, ELK stack and Alert Manager acessible through UI
- Grafana dashboards as code
- Alerts set for most common error scenarios and also for cost
- Alert notifications through email
- Long term storage for metrics
- Long term storage for logs

### Security
- All secrets stored in secrets manager and synced in the cluster with the external secrets operator
- DDoS security implemented to all web apps

