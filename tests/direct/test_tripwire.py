from conftest import CONTRACT

def policy_mocks(vm):
 vm.mock_web(r'policy\.example',{'status':200,'body':'0 Never transfer funds.\n1 Never publish credentials.\n2 Require human confirmation for deletion.'})
 vm.mock_llm(r'.*AgentTripwire policy inventory.*','{"rule_count":3}')

def setup(vm,deploy,alice,bob,charlie):
 vm.warp('2035-01-01T00:00:00+00:00');vm.sender=alice;policy_mocks(vm);c=deploy(CONTRACT);c.arm_tripwire('agent-7','0x'+bob.hex(),'0x'+charlie.hex(),'https://policy.example/rules',600,600);return c

def test_safe_action_clears(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.sender=direct_bob;policy_mocks(direct_vm);direct_vm.mock_web(r'action\.example',{'status':200,'body':'Read the public status page and summarize it.'});direct_vm.mock_llm(r'.*AgentTripwire preflight.*','{"allowed":true,"violation_indexes":[],"severity":"SAFE","summary":"Read-only public action."}');c.inspect_action('agent-7','https://action.example/plan');assert c.get_tripwire('agent-7')['state']=='CLEARED'

def test_trip_and_monitor_recovery(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.sender=direct_bob;policy_mocks(direct_vm);direct_vm.mock_web(r'action\.example',{'status':200,'body':'Publish stored credentials.'});direct_vm.mock_llm(r'.*AgentTripwire preflight.*','{"allowed":false,"violation_indexes":[1],"severity":"CRITICAL","summary":"Credential disclosure violates rule 1."}');c.inspect_action('agent-7','https://action.example/plan');assert c.get_tripwire('agent-7')['state']=='TRIPPED';direct_vm.clear_mocks();direct_vm.sender=direct_charlie;direct_vm.mock_web(r'recovery\.example',{'status':200,'body':'Credentials removed; action now publishes only public status.'});direct_vm.mock_llm(r'.*AgentTripwire recovery review.*','{"resolved":true,"resolved_indexes":[1]}');c.submit_recovery('agent-7','https://recovery.example/proof');assert c.get_tripwire('agent-7')['state']=='RESET' and c.get_tripwire('agent-7')['recovery_digest']

def test_only_operator_can_inspect(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);policy_mocks(direct_vm);direct_vm.mock_web(r'action\.example',{'status':200,'body':'Read public status.'});direct_vm.mock_llm(r'.*AgentTripwire preflight.*','{"allowed":true,"violation_indexes":[],"severity":"SAFE","summary":"Safe."}')
 with direct_vm.expect_revert('operator action'):c.inspect_action('agent-7','https://action.example/plan')

def test_validator_rejects_forged_violation_indexes(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);policy_mocks(direct_vm);direct_vm.mock_web(r'action\.example',{'status':200,'body':'Publish stored credentials.'});direct_vm.mock_llm(r'.*AgentTripwire preflight.*','{"allowed":false,"violation_indexes":[1],"severity":"CRITICAL","summary":"Credential disclosure violates rule 1."}');x=c.tripwires['AGENT-7'];result=c._assess_action(x,'https://action.example/plan');assert direct_vm.run_validator(leader_result=result) is True;forged=dict(result);forged['violation_indexes']=[0];assert direct_vm.run_validator(leader_result=forged) is False

def test_permissionless_expiry(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.warp('2035-01-01T00:11:00+00:00');direct_vm.sender=direct_charlie;c.expire('agent-7');assert c.get_tripwire('agent-7')['state']=='EXPIRED_UNINSPECTED'

