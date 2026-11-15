"""Where an app runs is Nomad's answer, not the index's."""

from avc.flows.apps import running_nodes


def test_running_nodes_are_those_with_a_running_allocation() -> None:
    allocs = """[
      {"NodeName": "node2", "ClientStatus": "running"},
      {"NodeName": "node1", "ClientStatus": "complete"},
      {"NodeName": "node3", "ClientStatus": "pending"}
    ]"""
    assert running_nodes(allocs) == ["node2"]


def test_no_allocations_and_no_answer_are_nowhere() -> None:
    assert running_nodes("[]") == []
    assert running_nodes("null") == []
    assert running_nodes("") == []
    assert running_nodes("Error querying job: 403") == []
