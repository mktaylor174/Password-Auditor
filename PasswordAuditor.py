# PasswordAuditor developed by Maggie Taylor
# Last updated: June 15, 2026

import secrets
import string
import argparse
import csv

# Function to generate a strong password
def generate_password(length=16):
    characters = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    secure_pass = False

    while not secure_pass:
        password = ''.join(
        secrets.choice(characters)
        for _ in range(length)
        )
        
        if (len(password) >= 12
            and any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in string.punctuation for c in password)
            ):            
            secure_pass = True

    return password

# Function to check password strength
def check_strength(password):
    score = 0

    if len(password) >= 12:
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(c.islower() for c in password):
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 3:
        return "Weak"

    elif score == 4:
        return "Moderate"

    else:
        return "Strong"

# Function to print out audit results for password checking
def audit_password(password):
    issues = []

    if len(password) < 12:
        issues.append("Password is shorter than 12 characters.")

    if not any(c.isupper() for c in password):
        issues.append("Missing uppercase letter.")

    if not any(c.islower() for c in password):
        issues.append("Missing lowercase letter.")

    if not any(c.isdigit() for c in password):
        issues.append("Missing number.")

    if not any(c in string.punctuation for c in password):
        issues.append("Missing special character.")

    return issues

# Function to audit tab-separated txt files of passwords
def audit_file(filename):
    results = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            password = line.strip()

            if not password:
                continue

            strength = check_strength(password)
            issues = audit_password(password)

            results.append({
                "password": password,
                "strength": strength,
                "issues": "; ".join(issues)
            })

    weak = sum(
        result["strength"] == "Weak"
        for result in results
    )

    moderate = sum(
        result["strength"] == "Moderate"
        for result in results
    )

    strong = sum(
        result["strength"] == "Strong"
        for result in results
    )

    print(f"Passwords analyzed: {len(results)}")
    print(f"Weak: {weak}")
    print(f"Moderate: {moderate}")
    print(f"Strong: {strong}")

    return results

# Function to generate a csv file containing the individual results of the file audit
def generate_csv(results):
    with open(
        "audit_results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Password",
            "Strength",
            "Issues"
        ])

        for result in results:

            writer.writerow([
                result["password"],
                result["strength"],
                result["issues"]
            ])

    print("CSV report generated: audit_results.csv")

# Function to generate a markdown file with the general results of the file audit
def generate_markdown(results):
    weak = sum(
        result["strength"] == "Weak"
        for result in results
    )

    moderate = sum(
        result["strength"] == "Moderate"
        for result in results
    )

    strong = sum(
        result["strength"] == "Strong"
        for result in results
    )

    with open(
        "password_report.md",
        "w",
        encoding="utf-8"
    ) as report:

        report.write("# Password Audit Report\n\n")

        report.write(
            f"Passwords analyzed: {len(results)}\n\n"
        )

        report.write(
            f"- Weak passwords: {weak}\n"
        )

        report.write(
            f"- Moderate passwords: {moderate}\n"
        )

        report.write(
            f"- Strong passwords: {strong}\n\n"
        )

        report.write(
            "## Sample Results\n\n"
        )

        report.write(
            "| Password | Strength |\n"
        )

        report.write(
            "|----------|----------|\n"
        )

        for result in results[:25]:
            report.write(
                f"| {result['password']} | {result['strength']} |\n"
            )

    print("Markdown report generated: password_report.md")

def main():
    parser = argparse.ArgumentParser(
        description="Password Generator and Security Auditor"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a secure password"
    )

    generate_parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Password length"
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Audit a password"
    )

    check_parser.add_argument(
        "password",
        help="Password to analyze"
    )

    file_parser = subparsers.add_parser(
        "audit-file",
        help="Audit passwords from a file"
    )

    file_parser.add_argument(
        "filename",
        help="Path to password file"
    )

    args = parser.parse_args()

    if args.command == "generate":
        password = generate_password(args.length)

        print("\nGenerated Password")
        print("------------------")
        print(password)

    elif args.command == "check":
        strength = check_strength(args.password)
        issues = audit_password(args.password)

        print("\nPassword Analysis")
        print("-----------------")
        print(f"Strength: {strength}")

        if issues:
            print("\nIssues Found:")
            for issue in issues:
                print(f"- {issue}")
        else:
            print("\nPassword passes all security checks.")

    elif args.command == "audit-file":
        results = audit_file(args.filename)
        generate_csv(results)
        generate_markdown(results)

if __name__ == "__main__":
    main()