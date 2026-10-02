"""
Seed a synthetic 3-email campaign sharing domain 'phish-server.com'.
Run: python scripts/seed_demo_campaign.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from neo4j_engine import seed_demo_data, correlate_campaigns, test_connection


def main():
    print("\n[SEED] Seeding demo campaign (3 emails sharing phish-server.com)")
    print("-" * 60)

    status = test_connection()
    print(f"Backend mode: {status.get('mode')} ({status.get('status')})")
    print(f"Message: {status.get('message', '')}\n")

    count = seed_demo_data()
    print(f"[OK] Inserted {count} new demo email(s)\n")

    print("[VERIFY] Querying correlate_campaigns()...")
    campaigns = correlate_campaigns()
    if campaigns:
        print(f"  Detected {len(campaigns)} campaign(s):")
        for c in campaigns:
            print(
                f"    - {c['campaign_id']}: {c['shared_ioc_type']} '{c['shared_ioc']}' "
                f"across {c['correlated_emails_count']} email(s)"
            )
    else:
        print("  [WARN] No campaigns detected")

    print("\n[DONE] Open the dashboard and go to Tab 5 to see the campaign table.\n")


if __name__ == "__main__":
    main()
