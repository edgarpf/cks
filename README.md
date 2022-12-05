# CKS

Create user:

```
openssl genrsa -out edgar.key 2048
openssl req -new -key edgar.key -out edgar.csr # only set Common Name = jane

# create CertificateSigningRequest with base64 edgar.csr
https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests
cat edgar.csr | base64 -w 0

k config set-credentials edgar --client-key=edgar.key --client-certificate=edgar.crt
k config set-context edgar --cluster=kubernetes --user=edgar
k config view
k config get-contexts
k config use-context edgar
```
Run two Docker containers app1 and app2 with the following attributes:
* they should run image nginx:alpine
* they should share the same PID kernel namespace
* they should run command sleep infinity
* they should run in the background (detached)
* Then check which container sees which processes and make sense of why.

```
docker run --name app1 -d nginx:alpine sleep infinity
docker exec app1 ps aux
docker run --name app2 --pid=container:app1 -d nginx:alpine sleep infinity
docker exec app1 ps aux
docker exec app2 ps aux
```
Run two Podman containers app1 and app2 with the following attributes:
* they should run image nginx:alpine
* they should share the same PID kernel namespace
* they should run command sleep infinity
* they should run in the background (detached)
Then check which container sees which processes and make sense of why.
```
podman run --name app1 -d nginx:alpine sleep infinity
podman exec app1 ps aux
podman run --name app2 --pid=container:app1 -d nginx:alpine sleep infinity
```
There are existing Pods in Namespace app .
We need a new default-deny NetworkPolicy named deny-out for all outgoing traffic from Namespace app .
It should still allow DNS traffic on port 53 TCP and UDP.
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-out
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
```
There are existing Pods in Namespace space1 and space2 .

We need a new NetworkPolicy named np that restricts all Pods in Namespace space1 to only have outgoing traffic to Pods in Namespace space2.

We also need a new NetworkPolicy named np that restricts all Pods in Namespace space2 to only have incoming traffic from Pods in Namespace space1.

The NetworkPolicies should still allow outgoing DNS traffic on port 53 TCP and UDP.

```
k get ns --show-labels
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space1
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
     - namespaceSelector:
        matchLabels:
         kubernetes.io/metadata.name: space2
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space2
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
   - from:
     - namespaceSelector:
        matchLabels:
         kubernetes.io/metadata.name: space1
```
Expose service
```
k -n namespace expose deploy deploy_name --port 80
```
Generate keys, secret and a Ingress that use the secret.
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt -subj "/CN=world.universe.mine/O=world.universe.mine"
kubectl -n world create secret tls ingress-tls --key cert.key --cert cert.crt
```
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: world
  namespace: world
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    nginx.ingress.kubernetes.io/use-regex: "true"
    nginx.ingress.kubernetes.io/rewrite-target: /$1
spec:
  ingressClassName: nginx
  tls:                            # add
  - hosts:                        # add
    - world.universe.mine         # add
    secretName: ingress-tls       # add
  rules:
  - host: "world.universe.mine"
    http:
      paths:
      - path: /europe
        pathType: Prefix
        backend:
          service:
            name: europe
            port:
              number: 80
      - path: /asia
        pathType: Prefix
        backend:
          service:
            name: asia
            port:
              number: 80
```
Create a NetworkPolicy named metadata-server In Namespace default which restricts all egress traffic to 1.1.1.1.
The NetworkPolicy should only affect Pods with label trust=nope .
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-server
  namespace: default
spec:
  podSelector:
    matchLabels:
      trust: nope
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 1.1.1.1/32
```
Use kube-bench to ensure 1.2.20 has status PASS.
```
kube-bench run --targets master
kube-bench run --targets master --check 1.2.20
```
Fix the /etc/kubernetes/manifests/kube-apiserver.yaml
```
...
containers:
  - command:
    - kube-apiserver
    - --profiling=false
...
    image: k8s.gcr.io/kube-apiserver:v1.22.2
...
```
Download the kubelet binary in the same version as the installed one.
```
VERSION=$(kubelet --version | cut -d ' ' -f2)
wget https://dl.k8s.io/$VERSION/kubernetes-server-linux-amd64.tar.gz
tar xzf kubernetes-server-linux-amd64.tar.gz
whereis kubelet
sha512sum /usr/bin/kubelet
sha512sum kubernetes/server/bin/kubelet
```
There are existing Namespaces ns1 and ns2 .
Create ServiceAccount pipeline in both Namespaces.
These SAs should be allowed to view almost everything in the whole cluster. You can use the default ClusterRole view for this.
These SAs should be allowed to create and delete Deployments in Namespaces ns1 and ns2.
Verify everything using kubectl auth can-i.
```
k -n ns1 create sa pipeline
k -n ns2 create sa pipeline

k get clusterrole view # there is default one
k create clusterrolebinding pipeline-view --clusterrole view --serviceaccount ns1:pipeline --serviceaccount ns2:pipeline

k create clusterrole pipeline-deployment-manager --verb create,delete --resource deployments

k -n ns1 create rolebinding pipeline-deployment-manager --clusterrole pipeline-deployment-manager --serviceaccount ns1:pipeline
k -n ns2 create rolebinding pipeline-deployment-manager --clusterrole pipeline-deployment-manager --serviceaccount ns2:pipeline

k auth can-i create deployments --as system:serviceaccount:ns1:pipeline -n ns1 # YES
k auth can-i update deployments --as system:serviceaccount:ns1:pipeline -n ns1 # NO
```
There is existing Namespace applications.
User smoke should be allowed to create and delete Pods, Deployments and StatefulSets in Namespace applications.
User smoke should have view permissions (like the permissions of the default ClusterRole named view ) in all Namespaces but not in kube-system.
User smoke should be allowed to retrieve available Secret names in Namespace applications. Just the Secret names, no data.
Verify everything using kubectl auth can-i.
```
k -n applications create role smoke --verb create,delete --resource pods,deployments,sts
k -n applications create rolebinding smoke --role smoke --user smoke

k get ns # get all namespaces
k -n applications create rolebinding smoke-view --clusterrole view --user smoke
k -n default create rolebinding smoke-view --clusterrole view --user smoke
k -n kube-node-lease create rolebinding smoke-view --clusterrole view --user smoke
k -n kube-public create rolebinding smoke-view --clusterrole view --user smoke
```
Create a new "user" that can communicate with K8s.
For this now:
Create a new KEY at /root/60099.key for user named 60099@internal.users
Create a CSR at /root/60099.csr for the KEY
```
openssl genrsa -out 60099.key 2048
openssl req -new -key 60099.key -out 60099.csr
# set Common Name = 60099@internal.users
```

You can use ***automountServiceAccountToken: false*** to disable the mounting of the ServiceAccount token into a Pod yaml file.

To see the logs:

```
/var/log/syslog
/var/log/pod
/var/log/containers
```
Create an EncryptionConfiguration file at /etc/kubernetes/etcd/ec.yaml and make ETCD use it.
One provider should be of type aesgcm with password this-is-very-sec . All new secrets should be encrypted using this one.
One provider should be the identity one to still be able to read existing unencrypted secrets.

```
mkdir -p /etc/kubernetes/etcd
echo -n this-is-very-sec | base64
```
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: dGhpcy1pcy12ZXJ5LXNlYw==
    - identity: {}
```
Go to /etc/kubernetes/manifests/kube-apiserver.yaml and pass the new argument:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
...
    - --encryption-provider-config=/etc/kubernetes/etcd/ec.yaml
...
    volumeMounts:
    - mountPath: /etc/kubernetes/etcd
      name: etcd
      readOnly: true
...
  hostNetwork: true
  priorityClassName: system-cluster-critical
  volumes:
  - hostPath:
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate
    name: etcd
...
```
You should install gVisor on the node node01 and make containerd use it.
There is install script /root/gvisor-install.sh which should setup everything, execute it on node node01.
```
scp gvisor-install.sh node01:/root
ssh node01
sh gvisor-install.sh
service kubelet status
```
Create a Pod named prime image nginx:alpine .
The container should run as privileged .
Install iptables (apk add iptables ) inside the Pod.
Test the capabilities using iptables -L .
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: prime
  name: prime
spec:
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: nginx:alpine
    name: prime
    securityContext:
      privileged: true
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```
```
k exec prime -- apk add iptables
k exec prime -- iptables -L
```
```
spec:
  replicas: 3
  selector:
    matchLabels:
      app: logger
  strategy: {}
  template:
    metadata:
      labels:
        app: logger
    spec:
      containers:
      - image: httpd:2.4.52-alpine
        name: httpd
        securityContext:
            allowPrivilegeEscalation: false
```

```
docker build -t base-image .
docker run --name c1 -d base-image
--show the user of process
docker exec c1 ps
--delete container
docker rm c1 --force
```

Example of a secure Dockerfile
```
FROM ubuntu:20.04
RUN apt-get update && apt-get -y install curl
ENV URL https://google.com/this-will-fail?secret-token=
RUN rm /usr/bin/bash
CMD ["sh", "-c", "curl --head $URL$TOKEN"]
```

Use ***strace*** to see which syscalls the following commands perform:
```
strace kill -9 1234
```
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: pod-ro
  name: pod-ro
  namespace: sun
spec:
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: busybox:1.32.0
    name: pod-ro
    securityContext:
      readOnlyRootFilesystem: true
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```
Configure the Apiserver for Audit Logging.
The log path should be /etc/kubernetes/audit-logs/audit.log on the host and inside the container.
The existing Audit Policy to use is at /etc/kubernetes/audit-policy/policy.yaml . The path should be the same on the host and inside the container.
Set argument --audit-log-maxsize=7
Set argument --audit-log-maxbackup=2

Edit /etc/kubernetes/manifests/kube-apiserver.yaml
```yaml
# add new Volumes
volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit-policy/policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /etc/kubernetes/audit-logs
      type: DirectoryOrCreate
# add new VolumeMounts
volumeMounts:
  - mountPath: /etc/kubernetes/audit-policy/policy.yaml
    name: audit-policy
    readOnly: true
  - mountPath: /etc/kubernetes/audit-logs
    name: audit-logs
    readOnly: false
# enable Audit Logs
spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit-policy/policy.yaml
    - --audit-log-path=/etc/kubernetes/audit-logs/audit.log
    - --audit-log-maxsize=7
    - --audit-log-maxbackup=2
```
There is an unwanted process running which listens on port 1234 .
Kill the process and delete the binary.
```
# using netstat
apt install net-tools
netstat -tulpan | grep 1234

# using lsof
lsof -i :1234

ls -l /proc/17773/exe # use your ID instead

kill 17773 # use your ID instead
rm /usr/bin/app1
```
Your team has decided to use kube-bench via a DaemonSet instead of installing via package manager.
Go ahead and remove the kube-bench package using the default package manager.
```
apt show kube-bench
apt remove kube-bench
```
