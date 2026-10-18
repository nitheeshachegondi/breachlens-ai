import pytest
from app import main
try: main.seed("breachlens"); OK = True
except Exception: OK = False
pytestmark = pytest.mark.skipif(not OK, reason="FalkorDB not running")
def real(): return main.paths(main.db().select_graph("breachlens"))
def test_three_paths_found(): assert len(real()) == 3
def test_patch_log4j_breaks_two_paths_and_one_remains():
    r = main.simulate("patch:log4j-core")
    assert len(r["removed"]) == 2 and len(r["remaining"]) == 1 and r["risk_after"] < r["risk_before"]
def test_simulation_does_not_touch_real_graph():
    main.simulate("isolate:api-service"); assert len(real()) == 3
def test_patching_spring_alone_leaves_all_paths(): assert len(main.simulate("patch:spring-framework")["remaining"]) == 3
