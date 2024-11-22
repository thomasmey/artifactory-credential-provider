# Kubernetes kubelet credentials provider for JFrog's Artifactory

See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/

This provider does fetch an ID token from Google's metadata server on GCE, does a token exchange with JFrog IDP and returns the access token to kubelet for image pull.
