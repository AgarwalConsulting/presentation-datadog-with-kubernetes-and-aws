layout: true

.signature[@algogrit]

---

class: center, middle

# DataDog with Kubernetes and AWS

Gaurav Agarwal

---
class: center, middle

## Setting up DataDog

---
class: center, middle

### [On Kubernetes](https://docs.datadoghq.com/containers/kubernetes/)

---
class: center, middle

### *Optional:* **Integrating with AWS**

.content-credits[https://docs.datadoghq.com/integrations/amazon_web_services/]

---
class: center, middle

#### *Optional:* **Integrating DataDog with AWS RDS (SQL Server, PostgreSQL, MySQL, etc.)**

---

#### **Steps:**

1️⃣ **Go to AWS Integration in DataDog**

- Navigate to **Integrations** → **AWS** in DataDog UI.
- Click **"Install Integration"** (if not installed).

2️⃣ **Set Up an IAM Role for DataDog**

- Create an **IAM Role** in AWS with a **CloudWatch Read-Only Policy**.
- Attach the following policies:
  - `CloudWatchReadOnlyAccess`
  - `AWSRDSReadOnlyAccess`
- Add a **trust policy** to allow DataDog to assume this role.

---

3️⃣ **Link DataDog to AWS**

- In DataDog, go to **AWS Integration** settings.
- Enter the **IAM Role ARN** created earlier.
- Select **RDS service** for monitoring.

4️⃣ **Enable Enhanced RDS Monitoring (Optional, Recommended)**

- In AWS Console, go to **RDS → Modify DB Instance**.
- Enable **Enhanced Monitoring** and select a **monitoring role**.
- Choose **Granularity** (1s, 5s, 10s, etc.).

---
class: center, middle

## Monitoring Kubernetes & Container Metrics with DataDog

---

### **🔹 Node Metrics**

- `kubernetes.cpu.usage.total` → CPU usage
- `kubernetes.memory.usage` → Memory usage
- `kubernetes.filesystem.usage` → Disk usage

### **🔹 Pod & Container Metrics**

- `kubernetes.containers.running` → Running containers
- `kubernetes.pods.ready` → Number of ready pods
- `kubernetes.container.cpu.usage` → Container CPU
- `kubernetes.container.memory.usage` → Container memory

### **🔹 Network Metrics**

- `kubernetes.network.rx_bytes` → Incoming network traffic
- `kubernetes.network.tx_bytes` → Outgoing network traffic

---
class: center, middle

### Monitoring Kubernetes Events & Logs

---
class: center, middle

`kubeStateMetricsEnabled: true`

---
class: center, middle

### Container-Level Monitoring (Docker & Kubernetes)

---
class: center, middle

```yaml
  processAgent:
    enabled: true
  containerRuntime:
    collectContainerCount: true
```

---

Key Container Metrics:

- `container.cpu.usage` → CPU % used

- `container.memory.usage` → Memory used

- `container.disk.read_bytes` → Disk reads

- `container.network.bytes_sent` → Network usage

---
class: center, middle

### Kubernetes Service Monitoring

Monitor high-level service health, request latency, and error rates

---
class: center, middle

```yaml
  apm:
    enabled: true
    env: production
```

---

Key Service Metrics:

- `service.response.time` → API latency

- `service.error.rate` → % of failed requests

- `service.request.count` → Total request count

---

## AWS RDS Metrics shipped via AWS Integration

- `aws.rds.cpuutilization`

- `aws.rds.database_connections`

- `aws.rds.query_execution_time`

---
class: center, middle

## Log Management with DataDog

---
class: center, middle

```yaml
    containerCollectAll: true  # Collect all container logs
```

---
class: center, middle

### Collecting AWS RDS Logs

---

#### Step 1: Enable RDS Log Export to CloudWatch:

1️⃣ Open **AWS Console → RDS → Databases**

2️⃣ Select your **RDS Instance**

3️⃣ Go to **Log Exports** and enable:

- **General Logs**
- **Slow Query Logs**
- **Error Logs**

4️⃣ Click **Save Changes**

---

#### Step 2: Forward CloudWatch Logs to DataDog

Use the AWS Lambda function provided by DataDog:

```bash
datadog-forwarder --function-name datadog-logs-forwarder
```

---
class: center, middle

### ElasticSearch Log Integration with DataDog

---

🔹 Option 1: Enable ElasticSearch Logs on EKS & EC2

🔹 Option 2: Forward ElasticSearch Logs via Logstash

---
class: center, middle

#### Distributed Tracing with DataDog APM

---
class: center, middle

Enabling APM in DataDog Agent (Kubernetes Helm)

```yaml
datadog:
  apm:
    enabled: true
  logs:
    enabled: true
```

---
class: center, middle

## DataDog Dashboards

---
class: center, middle

### Built-in Dashboards

---

#### ✅ Kubernetes Dashboard (EKS & EC2)

- **Go to** → `Dashboards → New Dashboard → Kubernetes`

- DataDog provides a **default Kubernetes dashboard**:

  - **Pod & Node CPU & Memory Usage**

  - **Pod Restarts & CrashLoops**

  - **Network Traffic**

  - **Kube API Server Requests**

---

#### ✅ **AWS Resource Dashboard**

- **Go to** → `Dashboards → New Dashboard → AWS`

- This includes built-in dashboards for:

  - **EC2 Instances (CPU, Memory, Disk IO)**

  - **RDS Query Performance & Slow Queries**

  - **S3 Storage & Errors**

  - **Lambda Execution Time & Invocations**

---
class: center, middle

## Alerting

---
class: center, middle

### Built-in Monitors (Alerts)

---

### 🚨 **Built-in Kubernetes Alerts**

- **Go to** → `Monitors → New Monitor → Kubernetes`

- Select pre-built alerts for:

  - **Node CPU or Memory Pressure**

  - **Pod CrashLoopBackOff**

  - **High API Server Latency**

  - **Failed Container Starts**

---

### 🚨 **Built-in AWS Alerts**

- **Go to** → `Monitors → New Monitor → AWS`

- Select from **default AWS alerts**, including:

  - **EC2 CPU Spikes**

  - **RDS High Query Latency**

  - **S3 5xx Errors**

  - **Lambda Execution Failures**

---
class: center, middle

### Anomaly Detection for Unusual Spikes

---

#### ✅ Kubernetes Anomalies

- **Pods Restarting More Than Usual**

- **Sudden Increase in API Latency**

- **Container CPU Spikes Compared to Baseline**

---

#### ✅ AWS Anomalies

- **EC2 CPU or Network Traffic Sudden Changes**

- **RDS Query Duration Irregular Spikes**

- **S3 Unexpected High Error Rate**

---
class: center, middle

## K8s Specific Troubleshooting

---
class: center, middle

### Kubernetes Network Performance Monitoring with DataDog

---
class: center, middle

`datadog.networkMonitoring.enabled`

---
class: center, middle

### **✅ Essential Network Performance Metrics**

---

| **Metric** | **Description** | **DataDog Metric Name** |
|------------|---------------|------------------|
| **Pod Network Traffic** | Measures ingress/egress traffic for pods | `kubernetes.pod.network.tx_bytes`, `kubernetes.pod.network.rx_bytes` |
| **Node Network Traffic** | Measures node-level network usage | `kubernetes.node.network.tx_bytes`, `kubernetes.node.network.rx_bytes` |
| **API Server Latency** | Tracks latency for requests to Kubernetes API | `kubernetes.apiserver.request.latency` |
| **DNS Resolution Time** | Measures Kubernetes DNS query performance | `kubernetes.dns.request_duration` |
| **Service Connectivity** | Monitors network reachability between services | `datadog.network.tcp.response_time` |
| **Packet Drops** | Detects lost packets due to network congestion | `kubernetes.network.dropped_packets` |
| **TCP Retransmissions** | Measures TCP retransmissions due to network issues | `kubernetes.network.tcp.retransmits` |

---
class: center, middle

*Exercise*: Creating a Network Performance Dashboard for K8s

---
class: center, middle

### Kubernetes Network Performance Monitoring with CNI & DataDog

---
class: center, middle

What is CNI in Kubernetes?

---

**Container Network Interface (CNI)** is the **networking layer** in Kubernetes responsible for:

✔ Assigning **IP addresses** to Pods

✔ Setting up **routes** for inter-pod communication

✔ Enforcing **network policies** for security

✔ Handling **network overlays** (if applicable)

---

**Popular CNIs** & How They Work:

| **CNI** | **Type** | **How it Works** |
|---------|---------|----------------|
| **Calico** | L3 | Uses BGP for pod networking & security policies |
| **Cilium** | L3/L7 | eBPF-based for efficient networking & observability |
| **Flannel** | L2 | Simple overlay networking with VXLAN |
| **AWS VPC CNI** | L3 | Assigns ENIs (Elastic Network Interfaces) directly in AWS VPC |
| **Weave** | L2/L3 | Uses VXLAN & IP routing for networking |

---
class: center, middle

📌 **Why This Matters?** Different CNIs expose **different metrics** that impact network monitoring.

---
class: center, middle

#### **📌 CNI-Specific Monitoring Strategies**

---

##### **✅ Cilium CNI Monitoring**

📌 **Monitor eBPF-based networking, L7 security, and service connectivity.**

1️⃣ **Enable Cilium Hubble for Observability**
```sh
helm upgrade --install cilium cilium/cilium \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true
```

2️⃣ **Metrics in DataDog**

- **Packet Drops**: `cilium.policy.drops`
- **L7 HTTP Request Latency**: `cilium.http.request_duration_seconds`
- **Service Connectivity**: `cilium.endpoint.state`

3️⃣ **Create Alert: High Network Latency Between Services**

```plaintext
avg:cilium.http.request_duration_seconds{*} by {service} > 0.5
```

🚨 **Triggers if HTTP request latency between services is >500ms.**

---

##### **✅ AWS VPC CNI Monitoring**

📌 **Monitor AWS ENI allocation, bandwidth limits & dropped packets.**

1️⃣ **Enable AWS VPC CNI Metrics Collection**

```sh
kubectl set env daemonset/aws-node -n kube-system ENABLE_VPC_CNI_PROMETHEUS=true
```

2️⃣ **Metrics in DataDog**

- **ENI Allocation**: `aws.vpc_cni.enis_allocated`
- **IP Addresses Per ENI**: `aws.vpc_cni.ipv4_addresses_per_eni`
- **Packet Drops**: `aws.vpc_cni.dropped_packets`

3️⃣ **Create Alert: Running Out of ENIs**

```plaintext
avg:aws.vpc_cni.enis_allocated{*} by {region} > 80
```

🚨 **Triggers if more than 80% of ENIs are allocated.**

---
class: center, middle

## Query Performance Monitoring (QPM) in SQL Server

---
class: center, middle

### **✅ Enable Query Execution Monitoring**

---

1️⃣ **Enable `sys.dm_exec_requests` Query Collection**

Edit `/etc/datadog-agent/conf.d/sqlserver.d/conf.yaml`:

```yaml
query_metrics:
  - name: "long_running_queries"
    query: |
      SELECT session_id, start_time, total_elapsed_time/1000 as duration_ms, command, database_id
      FROM sys.dm_exec_requests
      WHERE total_elapsed_time > 5000
    columns:
      - name: session_id
        type: tag
      - name: start_time
        type: tag
      - name: duration_ms
        type: gauge
      - name: command
        type: tag
```

2️⃣ **Restart DataDog Agent**

```sh
sudo systemctl restart datadog-agent
```

✅ **Now you can track long-running queries in DataDog!**

---
class: center, middle

## **🚀 DataDog AWS Integration Best Practices**

---
class: center, middle

Setting up **DataDog with AWS** requires best practices for **security, cost optimization, and effective monitoring**.

---

✔ **IAM Role Setup & Security Best Practices**

✔ **Optimizing AWS API Calls (Cost & Performance)**

✔ **Key AWS Services to Monitor**

✔ **Dashboards & Alerts Best Practices**

✔ **Anomaly Detection & Auto-Tagging**

✔ **Managing Multi-Account AWS Monitoring**

---

### **✅ Use IAM Role-Based Authentication**

🔹 Instead of static access keys, **create an IAM Role** for DataDog with cross-account access.

🔹 This improves **security** and avoids credential leaks.

### **✅ Least Privilege IAM Permissions**

Assign only the necessary permissions. **Use AWS Managed Policies**

---
class: center, middle

✅ **Avoid using `AdministratorAccess`** to reduce security risks.

---

### **✅ Use AWS Tag-Based Filtering**

Instead of pulling **all AWS services**, use tags to filter resources.

📌 **Example: Allow only resources with `Environment=Production`**

1️⃣ Go to **DataDog → AWS Integration**

2️⃣ Under **"Limit metrics collection by tag"**, add:
   ```yaml
   Environment:Production
   Service:WebApp
   ```

✅ This reduces unnecessary API calls and cost!

---

### **✅ Reduce High-Frequency API Calls**

Some AWS API calls (like `DescribeInstances`) can be expensive.

📌 **Best Practices:**

- **Use CloudWatch Metrics** instead of `DescribeInstances` for EC2 metrics.

- **Enable CloudWatch Metric Streams** for real-time, cost-efficient monitoring.

- **Disable Unused AWS Services** in DataDog integration.

---

### **✅ EC2 & Auto Scaling**

✔ Track **CPU, Memory, Disk, Network** (`aws.ec2.cpuutilization`)

✔ Monitor **Auto Scaling events**

✔ Alert on **high CPU, memory exhaustion, or instance failures**

---

### **✅ RDS (MySQL, PostgreSQL, SQL Server)**

✔ **Key Metrics:**

- CPU Utilization (`aws.rds.cpuutilization`)

- Active Connections (`aws.rds.database_connections`)

- Read/Write Latency (`aws.rds.read_latency`)

---

| **Metric** | **Description** | **DataDog Metric** |
|------------|---------------|------------------|
| **CPU Utilization** | Tracks SQL Server CPU load | `aws.rds.cpuutilization` |
| **Memory Usage** | Measures available memory | `aws.rds.freeablememory` |
| **Read/Write Latency** | Disk I/O performance | `aws.rds.read_latency`, `aws.rds.write_latency` |
| **Database Connections** | Active connections count | `aws.rds.database_connections` |
| **Deadlocks** | Number of deadlocks detected | `aws.rds.deadlocks` |
| **Long-Running Queries** | Tracks slow queries | `sqlserver.queries.slow` |
| **Lock Wait Time** | Time spent waiting for locks | `sqlserver.lock_waits` |

---

### **✅ Kubernetes (EKS) & Containers**

✔ **Monitor Cluster Health (`aws.eks.node_count`)**

✔ **Track Pod CPU/Memory Usage**

✔ **Enable Log Collection with AWS FluentBit**

---

### **✅ Lambda & Serverless**

✔ Monitor **Cold Start Latency (`aws.lambda.duration`)**

✔ Track **Invocation Errors (`aws.lambda.errors`)**

---
class: center, middle

## **🔒 Security & Incident Response in DataDog**

---
class: center, middle

DataDog provides **security monitoring, anomaly detection, and incident response tools** to detect and mitigate threats in cloud environments.

---

✔ **Security Monitoring for AWS, Kubernetes, and EC2**

✔ **Threat Detection with Logs & Metrics**

✔ **Anomaly Detection & Alerts**

✔ **Incident Response & Forensics**

✔ **Compliance & Audit Logging**

---

### **✅ Enable Security Monitoring in DataDog**

Security monitoring requires **DataDog Security Monitoring** (SIEM) and **log ingestion**.

📌 **To enable security monitoring:**

1️⃣ **Go to** `Security → Security Signals`

2️⃣ **Enable CloudTrail, VPC Flow Logs, Kubernetes Logs, and System Logs**

3️⃣ Set up **Security Rules** to detect unauthorized access

---

📌 **Example: Detect AWS Root User Login**

1️⃣ **Go to** `Security → Rules`
2️⃣ Create a new rule:

```yaml
security.rule:
  name: "AWS Root User Login"
  query: 'service:aws.cloudtrail @userIdentity.type:Root'
  severity: "high"
  notification: "@security-team"
```

🚨 **Triggers an alert if AWS root user logs in.**

---

### **✅ Security Log Monitoring**

Collect logs from:

- **AWS CloudTrail** (IAM activity, unauthorized access)

- **VPC Flow Logs** (network anomalies)

- **EC2 & Kubernetes Logs** (process anomalies)

- **Application Logs** (authentication failures)

---

📌 **Example: Monitor Unauthorized SSH Access on EC2**

1️⃣ **Enable log collection:**

```yaml
logs_enabled: true
```

2️⃣ **Create a log filter rule:**

```yaml
logs:
  - type: file
    path: /var/log/auth.log
    source: ssh
    service: security
```

3️⃣ **Set up a Security Rule:**

```yaml
security.rule:
  name: "Unauthorized SSH Access"
  query: 'service:ssh @status:failed'
  severity: "medium"
  notification: "@security-team"
```

🚨 **Triggers an alert when an SSH login fails multiple times.**

---

### **✅ Enable Anomaly Detection**

1️⃣ **Go to** `Monitors → New Monitor → Anomaly Detection`

2️⃣ Choose **metrics like CPU spikes, network traffic surges, or unauthorized logins**

3️⃣ Set up thresholds for normal vs. abnormal behavior

---

📌 **Example: Detect Unusual Traffic in Kubernetes**

```yaml
avg:kubernetes.network.tx{namespace:prod} by {pod} > anomaly("basic", 2, direction=above)
```

🚨 **Triggers an alert when outbound traffic spikes unexpectedly.**

---

📌 **Common Security Anomaly Alerts**

| **Threat** | **Metric/Log** | **DataDog Alert** |
|------------|--------------|------------------|
| **DDoS Attack** | High incoming traffic | `aws.vpc.network_in > anomaly(3x)` |
| **Brute Force SSH Attack** | Failed SSH logins | `service:ssh @status:failed > 5 times in 10 min` |
| **Unauthorized API Access** | AWS CloudTrail logs | `@eventName:AuthorizeSecurityGroupIngress` |
| **Container Escape Attempt** | K8s audit logs | `kubernetes.audit @event:exec into privileged container` |

---
class: center, middle

✅ **Security anomalies are automatically flagged in DataDog.**

---

### **✅ Set Up Incident Management in DataDog**

📌 **Steps to Create an Incident Response Workflow:**

1️⃣ **Go to** `Incident Management → Create Incident`

2️⃣ **Define Severity Levels:**

- 🔴 **Critical** (Service down, data breach)
- 🟠 **High** (Unauthorized access, API abuse)
- 🟡 **Medium** (Suspicious login attempt)

3️⃣ **Assign Teams** (Security, DevOps, IT)

4️⃣ **Attach Logs, Metrics, Dashboards for Analysis**

---

📌 **Example: Security Incident Response for EC2 Compromise**

1️⃣ **Detect Unauthorized Access:**

- **Alert Triggered:** "Root login detected from unknown IP"

2️⃣ **Investigate Logs & Network Traffic:**

- **Check CloudTrail logs:**

```sh
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
```

- **Inspect EC2 network traffic:**

```sh
aws ec2 describe-flow-logs
```

3️⃣ **Mitigate the Threat:**

- 🚨 **Revoke compromised IAM keys**
- 🔒 **Restrict security group rules**
- 🛑 **Quarantine the instance**

---

### **✅ Enable AWS Compliance Monitoring**

📌 **To enable compliance monitoring:**

1️⃣ **Go to** `Security → Compliance Monitoring`

2️⃣ Enable **CIS AWS Foundations Benchmark**

3️⃣ Monitor for:

- **Public S3 Buckets**

- **Unencrypted Databases**

- **Overly Permissive IAM Roles**

---

📌 **Example: Detect Publicly Accessible S3 Buckets**

```yaml
security.rule:
  name: "S3 Bucket Publicly Accessible"
  query: 'service:aws.s3 @acl:public-read OR @acl:public-write'
  severity: "critical"
  notification: "@security-team"
```

🚨 **Triggers an alert when an S3 bucket is exposed to the public.**

---

📌 **Example: Detect Unrestricted Security Groups**

```yaml
security.rule:
  name: "Security Group Open to the World"
  query: 'service:aws.ec2 @IpPermissions:0.0.0.0/0'
  severity: "high"
  notification: "@security-team"
```

🚨 **Notifies if an EC2 security group is open to the public.**

---
class: center, middle

## Database Monitoring (AWS SQL Server on RDS)

---
class: center, middle

📌 **Why It Matters**: Database performance issues can cause **slow APIs, increased latencies, and application crashes**.

---

- Supports **AWS RDS (SQL Server)** with query performance insights.

- Query performance insights (**slow queries, deadlocks, missing indexes**).

- **Connections & Locks Monitoring**: Track open connections, transaction locks.

- **Query Execution Plans**: Analyze how SQL queries execute.

- **Replication & Backup Monitoring**: Ensure database replication works as expected.

---

🔹 **How It Works**:

- Enable **RDS Enhanced Monitoring** in AWS.

- Connect DataDog with **AWS Integration** for automatic ingestion of RDS metrics.

- Use **Query Performance Monitoring (QPM)** to track execution times.

---
class: center, middle

*Example Use Case*: A **Java-based API running on Kubernetes** is slow when querying SQL Server. DataDog detects that a **missing index** is causing a **full table scan** on a large table. Adding the index **reduces query execution time from 2.5s to 200ms**.

---

class: center, middle

Code
https://github.com/AgarwalConsulting/presentation-datadog-with-kubernetes-and-aws

Slides
https://datadog-with-kubernetes-and-aws.slides.AgarwalConsulting.com
