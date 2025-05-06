import boto3

def find_firewall_risks():
    ec2 = boto3.client("ec2")
    groups = ec2.describe_security_groups()["SecurityGroups"]

    with open("logs/violations.log", "a") as log:
        log.write("\n### Security Group Violations ###\n")
        for sg in groups:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        log.write(f"[FW] Open port {port} to the world in SG: {sg['GroupId']}\n")
