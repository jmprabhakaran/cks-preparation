# CKS  Preparation

Understanding Kubernetes Attack Surface 
4C's of Cloud Native Security - Cloud, Cluster, Container, Code 
Cluster Setup and Hardening 
CIS Benchmarks - Security Benchmark(Physical devices(USB), Access(sudo), Network(configure firewall/iptables), Services(only necessasary services), Filesystem(right permissions are set), Logging and auditing)
CIS - OS, Cloud, Mobile, Network, Desktop Software, Server Software, Databases etc 
CIS-CAT(R) Lite
CIS-CAT Pro Assessor tool called Assessor-CLI
#!/bin/sh

# Absolute path to this script, e.g. /home/user/bin/foo.sh
SCRIPT=$(readlink -f "$0")
# Absolute path this script is in, thus /home/user/bin
SCRIPTPATH=$(dirname "$SCRIPT")

JAVA=java
MAX_RAM_IN_MB=2048
DEBUG=0

which $JAVA 2>&1 > /dev/null

if [ $? -ne "0" ]; then
        echo "Error: Java is not in the system PATH."
        exit 1
fi

JAVA_VERSION_RAW=`$JAVA -version 2>&1`

echo $JAVA_VERSION_RAW | grep 'version\s*\"\(\(1\.8\.\)\|\(9\.\)\|\([1-9][0-9]\.\)\)' 2>&1 > /dev/null

if [ $? -eq "1" ]; then

        echo "Error: The version of Java you are attempting to use is not compatible with CISCAT:"
        echo ""
        echo $JAVA_VERSION_RAW
        echo ""
        echo "You must use Java 1.8.x, or higher. The most recent version of Java is recommended."
        exit 1;
fi

if [ $DEBUG -eq "1" ]; then
        echo "Executing CIS-CAT Pro Assessor from $SCRIPTPATH"
        $JAVA -Xmx${MAX_RAM_IN_MB}M -jar $SCRIPTPATH/Assessor-CLI.jar "$@" --verbose
else
        $JAVA -Xmx${MAX_RAM_IN_MB}M -jar $SCRIPTPATH/Assessor-CLI.jar "$@"
fi

sh ./Assessor-CLI.sh -i -rd /var/www/html/ -nts -rp index

CIS-CAT Lite supports only Windows 10, Ubuntu, Google Chrome and MacOS
CIS-CAT Pro supports Kubernetes 
https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/cis-benchmarks-supported-by-cis-cat-pro/
https://learn.cisecurity.org/l/799323/2020-07-22/28v4r
kube-bench - open source tool from Aqua Security, can be deployed as docker container/pod in k8s/binary/compile from source 
https://github.com/aquasecurity/kube-bench

wget https://github.com/aquasecurity/kube-bench/releases/download/v0.6.5/kube-bench_0.6.5_linux_amd64.tar.gz
tar -xvf kube-bench_0.6.5_linux_amd64.tar.gz
./kube-bench --config-dir cfg --config cfg/config.yaml 

Fix this failed test 1.3.1 Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --terminated-pod-gc-threshold=10.
It should look like below after modification
  containers:
  - command:
    - kube-controller-manager
    - --allocate-node-cidrs=true
    - --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf
    - --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf
    - --bind-address=127.0.0.1
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --cluster-cidr=10.244.0.0/16
    - --cluster-name=kubernetes
    - --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt
    - --cluster-signing-key-file=/etc/kubernetes/pki/ca.key
    - --controllers=*,bootstrapsigner,tokencleaner
    - --kubeconfig=/etc/kubernetes/controller-manager.conf
    - --leader-elect=true
    - --port=0
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --root-ca-file=/etc/kubernetes/pki/ca.crt
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key
    - --service-cluster-ip-range=10.96.0.0/12
    - --use-service-account-credentials=true
    - --terminated-pod-gc-threshold=10

Fix this failed test 1.3.6 Ensure that the RotateKubeletServerCertificate argument is set to true
Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --feature-gates=RotateKubeletServerCertificate=true.
It should look like below after modification

  containers:
  - command:
    - kube-controller-manager
    - --allocate-node-cidrs=true
    - --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf
    - --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf
    - --bind-address=127.0.0.1
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --cluster-cidr=10.244.0.0/16
    - --cluster-name=kubernetes
    - --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt
    - --cluster-signing-key-file=/etc/kubernetes/pki/ca.key
    - --controllers=*,bootstrapsigner,tokencleaner
    - --kubeconfig=/etc/kubernetes/controller-manager.conf
    - --leader-elect=true
    - --port=0
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --root-ca-file=/etc/kubernetes/pki/ca.crt
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key
    - --service-cluster-ip-range=10.96.0.0/12
    - --use-service-account-credentials=true
    - --terminated-pod-gc-threshold=10
    - --feature-gates=RotateKubeletServerCertificate=true

Fix this failed test 1.4.1: Ensure that the --profiling argument is set to false
Set --profiling=false in /etc/kubernetes/manifests/kube-scheduler.yaml so it looks like below
  - command:
    - kube-scheduler
    - --authentication-kubeconfig=/etc/kubernetes/scheduler.conf
    - --authorization-kubeconfig=/etc/kubernetes/scheduler.conf
    - --bind-address=127.0.0.1
    - --kubeconfig=/etc/kubernetes/scheduler.conf
    - --leader-elect=true
    - --port=0
    - --profiling=false
	
Run the kube-bench test again and ensure that all tests for the fixes we implemented now pass
- 1.3.1 Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
- 1.3.6 Ensure that the RotateKubeletServerCertificate argument is set to true
- 1.4.1: Ensure that the --profiling argument is set to false
Run below command
./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml


Kubernetes Security Primitives
Secure Hosts - Password based authentication disabled, SSH Key based authentication
kube-apiserver - controlling access to api server (who can access & what they can do)
who - Files (Username/Password, Username/Tokens), Certificates, External auth providers - LDAP, Service Accounts	
what - RBAC Auth, ABAC Auth, Node Auth, Webhook mode
TLS Certificates
Network Policies 
