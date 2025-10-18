## Kube-VIP and Kube-VIP-Cloud-Controller in This K3s Setup

In this cluster, **Kube-VIP** and **Kube-VIP-Cloud-Controller** provide high-availability networking during the initial bootstrap phase — before deploying **MetalLB** as the full service load balancer for application workloads.

### Kube-VIP: Control Plane High-Availability
- Deployed as a **DaemonSet** across all control-plane nodes.
- Manages the virtual IP defined by `{{ k3s_registration_address }}`, which serves as the stable API endpoint for the K3s control plane.
- Operates in **ARP mode**, advertising the virtual IP only from the node currently holding the kube-vip leader lease.
- Provides transparent failover of the Kubernetes API endpoint if any control-plane node becomes unavailable.
- Configured only for control-plane HA — it does *not* provide Service-level load balancing.

### Kube-VIP-Cloud-Controller: Namespace-Scoped Service LoadBalancer
- Runs as a **Deployment** in the `kube-system` namespace.
- Functions as a lightweight **cloud-controller-manager** for bare-metal clusters.
- Monitors Kubernetes `Service` objects of type `LoadBalancer` and assigns external IPs based on the configuration in the `kubevip` ConfigMap.
- In this configuration, it is scoped specifically to the `argocd` namespace:
  ```yaml
  data:
    cidr-argocd: "{{ argocd_external_ip }}"
  ```
- This enables only the `argocd-server` Service to receive a LoadBalancer IP, defined by `{{ argocd_external_ip }}`, while all other Services remain pending until a broader Service LB solution (MetalLB) is deployed.

### Transition Plan to MetalLB
- Once **MetalLB** is installed via ArgoCD, it becomes the **primary Service LoadBalancer** for all application namespaces.
- Kube-VIP continues to provide:
  - **Control-plane HA** via `{{ k3s_registration_address }}`
  - **ArgoCD access** via `{{ argocd_external_ip }}`
- MetalLB will manage all other Service LoadBalancers (e.g., Traefik, Grafana, and application workloads) using its own IP pools defined in its Helm values or CRDs.

This staged setup establishes a clean and reliable bootstrap path:
1. **Kube-VIP** → Ensures the K3s control plane remains highly available via `{{ k3s_registration_address }}`.
2. **Kube-VIP-Cloud-Controller** → Exposes the ArgoCD Service early using `{{ argocd_external_ip }}`.
3. **MetalLB** → Assumes global Service LoadBalancer responsibilities once deployed.

Together, these components deliver a resilient transition from single-namespace bootstrap networking to full bare-metal load balancing, without conflicting IP ownership or downtime.

## Generating the kube-vip Daemonset

To set up kube-vip as an HA Load Balancer using a daemonset, follow the instructions from the [kube-vip documentation](https://kube-vip.io/docs/installation/daemonset/#kube-vip-as-ha-load-balancer-or-both). By default, this configuration uses ARP to provide **control-plane high availability only** — it advertises the Kubernetes API server VIP, but **does not handle Kubernetes `Service` resources** unless explicitly configured.

If you are using the **kube-vip cloud controller** (`kube-vip-cloud-provider`) to assign external IPs to `LoadBalancer` services, you **must also enable services mode** in the kube-vip DaemonSet. This is done by passing the `--services` flag or setting the following environment variables in the DaemonSet:

```yaml
- name: svc_enable
  value: "true"
```

Without this flag, the cloud controller may assign IPs from the `kubevip` ConfigMap, but the DaemonSet will not bind or advertise those IPs on any node. This results in `EXTERNAL-IP <pending>` and broken or unreachable services.

### Prerequisites

Set the following environment variables before generating the daemonset:

```bash
export VIP=192.168.90.98
export INTERFACE=eth0
export KVVERSION=$(curl -sL https://api.github.com/repos/kube-vip/kube-vip/releases | jq -r ".[0].name")
```

### Aliases for Kube-vip

You can create aliases for easy access to the kube-vip commands:

```bash
alias kube-vip="ctr image pull ghcr.io/kube-vip/kube-vip:$KVVERSION; ctr run --rm --net-host ghcr.io/kube-vip/kube-vip:$KVVERSION vip /kube-vip"
alias kube-vip="podman run --network host --rm ghcr.io/kube-vip/kube-vip:$KVVERSION"
```

### Generate the Daemonset

Run the following command to generate the kube-vip daemonset:

```bash
kube-vip manifest daemonset \
  --interface $INTERFACE \
  --address $VIP \
  --inCluster \
  --taint \
  --controlplane \
  --services \
  --arp \
  --leaderElection \
  --leaseDuration 15 \
  --leaseRenewDuration 10 \
  --leaseRetry 2
```

This command creates a daemonset configuration that uses the specified VIP and network interface. The options provided configure the load balancer's behavior and cluster integration.

Here’s the updated section for your `roles/kube_vip/templates/30-kube-vip-daemonset.yaml` file. This includes the necessary substitutions and post-editing requirements for the Ansible variables.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    app.kubernetes.io/name: kube-vip-ds
    app.kubernetes.io/version: {{ kube_vip_version }}  # Update this variable to match your Ansible variable for kube_vip_version
  name: kube-vip-ds
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kube-vip-ds
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kube-vip-ds
        app.kubernetes.io/version: {{ kube_vip_version }}  # Ensure this matches the value you set for kube_vip_version in your Ansible playbook
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role.kubernetes.io/master
                operator: Exists
            - matchExpressions:
              - key: node-role.kubernetes.io/control-plane
                operator: Exists
      containers:
      - args:
        - manager
        env:
        - name: vip_arp
          value: "true"
        - name: port
          value: "6443"
        - name: vip_nodename
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: vip_interface
          value: eth0  # Ensure the interface value matches what you are using in your environment
        - name: vip_subnet
          value: "32"
        - name: dns_mode
          value: first
        - name: cp_enable
          value: "true"
        - name: cp_namespace
          value: kube-system
        - name: svc_enable
          value: "true"
        - name: svc_leasename
          value: plndr-svcs-lock
        - name: vip_leaderelection
          value: "true"
        - name: vip_leasename
          value: plndr-cp-lock
        - name: vip_leaseduration
          value: "15"
        - name: vip_renewdeadline
          value: "10"
        - name: vip_retryperiod
          value: "2"
        - name: address
          value: {{ k3s_registration_address }}  # Update with your Ansible variable for registration address
        - name: prometheus_server
          value: :2112
        image: ghcr.io/kube-vip/kube-vip:{{ kube_vip_version }}  # Match with your kube_vip_version variable
        imagePullPolicy: IfNotPresent
        name: kube-vip
        resources: {}
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
            drop:
            - ALL
      hostNetwork: true
      serviceAccountName: kube-vip
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
  updateStrategy: {}
```

## Post-Editing Requirements

After editing `30-kube-vip-daemonset.yaml`, ensure to perform the following substitutions in your Ansible variables:

1. **`kube_vip_version`**: Make sure this variable is defined in your Ansible variables and matches the desired version of kube-vip you're deploying.
2. **`k3s_registration_address`**: Define this variable in your playbook, providing the address that kube-vip will use as its service registration address.
3. **`vip_interface`**: Confirm that the value `eth0` is correct for your networking setup or modify it as necessary for your environment.

These substitutions will ensure that the kube-vip daemonset functions correctly with your Ansible deployment.
