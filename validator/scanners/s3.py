import boto3

def find_s3_risks():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    with open("logs/violations.log", "a") as log:
        log.write("\n### S3 Bucket Violations ###\n")
        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    if "AllUsers" in str(grant) or "AuthenticatedUsers" in str(grant):
                        log.write(f"[S3] Public bucket detected: {name}\n")
            except Exception as e:
                log.write(f"[S3] Error scanning bucket {name}: {str(e)}\n")
