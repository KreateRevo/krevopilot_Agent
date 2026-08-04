# Safe release order

This repository is the customer-installed KrevoPilot Agent source.

Before publishing:

1. Run `python scripts/verify_release.py --chart-dir charts/krevopilot-agent`.
2. Run `python -m unittest -v test_agent.py`.
3. Build and push the immutable agent image.
4. Package and publish the matching Helm chart.
5. Verify both artifacts are publicly resolvable.
6. Only then update KrevoPilot's advertised release policy.

Never advertise a chart or image first. The platform must continue to recommend
the last confirmed published release until both new artifacts are available.
