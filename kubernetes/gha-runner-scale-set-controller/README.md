## Helm chart
https://github.com/actions/actions-runner-controller/tree/master/charts/gha-runner-scale-set-controller

## Manual steps to install the controller for debugging purposes
```bash
NAMESPACE="arc-systems"
helm install arc \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller
```
