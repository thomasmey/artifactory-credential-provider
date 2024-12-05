# Kubernetes kubelet credentials provider for JFrog's Artifactory

See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/

This provider does fetch an ID token from Google's metadata server on GCE, does a token exchange with JFrog IDP and returns the access token to kubelet for image pull.

# Installation

## GKE

1. Get cluster credentials `gcloud container clusters get-credentials --zone europe-west10-a cluster-1`
2. Create registry secret `kubectl create secret docker-registry registry --docker-server=registry.m3y3r.de --docker-username=acr --docker-password=gxc8ivHAZRZtk3Uj9vMW`
3. Modify manifests/installer.yaml to your needs
4. Install DaemonSet to your cluster with `kubectl apply -f manifests/installer.yaml`

# Configuring Artifactory for usage with GCP GKE

GCP IAM OpenID config is available here https://accounts.google.com/.well-known/openid-configuration

In Artifactory create an new "OIDC Integration":
- Provider Name: "gcp"
- Provider Type: "Generic OpenID Connect"
- Provider URL:  "https://accounts.google.com"
- Audience:      "artifactory-idp"
- Token Issuer:  "https://accounts.google.com"

Add an new identity mapping:

- Name:          "GCE Service Account"
- Priority:      100
- Claims JSON:   {"email":"405721773632-compute@developer.gserviceaccount.com"}'
(or any other claim from you GCP identity token)
- Access Token Settings
- Token Scope:   "User"
- User:          "Your-Artifactory-User, e.g. docker"
- Service:       "artifactory"
- Token Expiry:  "10"

# Test without registry secret

Run `kubectl run pulltest --image=trialp6kynx.jfrog.io/docker-trial/fedora:latest -t -i --rm=true`
