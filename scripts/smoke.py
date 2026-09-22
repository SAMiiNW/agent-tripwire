import json
import re
import time
from pathlib import Path

from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet

ROOT = Path(__file__).parents[1]
ENV = ROOT.parents[3] / "accounts.env"
manifest = json.loads((ROOT / "deployment.json").read_text())


def secret(slot: int) -> str:
    text = ENV.read_text()
    return re.search(rf'^ACCOUNT_{slot}_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)', text, re.M).group(1).strip()


def finalized(client, tx):
    receipt = client.wait_for_transaction_receipt(transaction_hash=tx, wait_until="finalized", retries=180, interval=5000, full_transaction=True)
    assert "MAJORITY_AGREE" in str(receipt.get("result_name", "")).upper()
    leader = ((receipt.get("consensus_data", {}).get("leader_receipt") or [{}])[0]).get("execution_result")
    assert str(leader).upper() == "SUCCESS"
    return str(tx)


owner = create_account(account_private_key=secret(1))
operator = create_account(account_private_key=secret(2))
monitor = create_account(account_private_key=secret(3))
client = create_client(chain=studionet, account=owner)
record = "REMEDIATION-" + str(int(time.time()))
policy = "https://raw.githubusercontent.com/SAMiiNW/agent-tripwire/4907501/evidence/policy.txt"
tx = client.write_contract(
    address=manifest["contractAddress"],
    function_name="arm_tripwire",
    args=[record, operator.address, monitor.address, policy, 600, 600],
    value=0,
)
proof = {"recordId": record, "armTransaction": finalized(client, tx)}
proof["state"] = client.read_contract(address=manifest["contractAddress"], function_name="get_tripwire", args=[record])["state"]
print(json.dumps(proof))
