# Kubernetes kubelet credentials provider for JFrog's Artifactory

See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/

This provider does fetch an ID token from Google's metadata server on GCE, does a token exchange with JFrog IDP and returns the access token to kubelet for image pull.

# Installation
## GKE

1. Get cluster credentials `gcloud container clusters get-credentials --zone europe-west10-a cluster-1`
2. Create registry secret `kubectl create secret docker-registry registry --docker-server=registry.m3y3r.de --docker-username=guest --docker-password=ASKME`
3. Modify manifests/installer.yaml to your needs
4. Install DaemonSet to your cluster with `kubectl apply -f installer.yaml`

# Configuring Artifactory for usage with GCP GKE

OpenID Provider URL https://accounts.google.com/.well-known/openid-configuration
