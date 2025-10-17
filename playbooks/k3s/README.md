# management

## Post Installation
Follow the steps to complete the argocd installation:
1. Login using the CLI
Using the username admin and password, login to Argo CD's IP or hostname:

```
argocd login <ARGOCD_SERVER>
```

2. Register external clusters to deploy apps to
This step registers a cluster's credentials to Argo CD, and is only necessary when deploying to an external cluster. When deploying internally (to the same cluster that Argo CD is running in), https://kubernetes.default.svc should be used as the application's K8s API server address.

First list all clusters contexts in your current kubeconfig:

```
kubectl config get-contexts -o name
```

Choose a context name from the list and supply it to argocd cluster add CONTEXTNAME. For example, for docker-desktop context, run:

```
argocd cluster add docker-desktop
```

The above command installs a ServiceAccount (argocd-manager), into the kube-system namespace of that kubectl context, and binds the service account to an admin-level ClusterRole. Argo CD uses this service account token to perform its management tasks (i.e. deploy/monitoring).
