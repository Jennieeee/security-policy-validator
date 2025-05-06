from scanners import iam, s3, firewall

def main():
    print(" Running Security Policy Validator...\n")

    iam.find_iam_risks()
    s3.find_s3_risks()
    firewall.find_firewall_risks()

    print("\n Scan complete! Check logs/violations.log for results.")

if __name__ == "__main__":
    main()
