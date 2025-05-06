import boto3

def find_iam_risks():
    client = boto3.client('iam')
    policies = client.list_policies(Scope='Local')['Policies']

    with open("logs/violations.log", "a") as log:
        log.write("### IAM Policy Violations ###\n")
        for policy in policies:
            policy_arn = policy["Arn"]
            version = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            )
            doc = version["PolicyVersion"]["Document"]
            statements = doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                    log.write(f"[IAM] Over-permissive policy: {policy_arn}\n")
