import json
from unittest.mock import MagicMock, create_autospec

import pytest
from _pytest.outcomes import fail
from databricks.labs.blueprint.parallel import ManyError
from databricks.labs.blueprint.tui import MockPrompts
from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import DatabricksError, NotFound, ResourceDoesNotExist
from databricks.sdk.service import iam
from databricks.sdk.service.iam import ComplexValue, Group, ResourceMeta

from databricks.labs.ucx.framework.crawlers import SqlBackend
from databricks.labs.ucx.workspace_access.groups import (
    ConfigureGroups,
    GroupManager,
    MigratedGroup,
    MigrationState,
)
from tests.unit.framework.mocks import MockBackend


def test_snapshot_with_group_created_in_account_console_should_be_considered():
    backend = MockBackend()
    ws = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    ws.groups.list.return_value = [group]
    account_admins_group = Group(id="1234", external_id="1234", display_name="de")
    ws.groups.get.return_value = group
    ws.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    group_manager = GroupManager(backend, ws, inventory_database="inv")
    res = group_manager.snapshot()
    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="de",
            temporary_name="ucx-renamed-de",
            members='[{"display": "test-user-1", "value": "20"}, {"display": "test-user-2", "value": "21"}]',
            external_id="1234",
            roles='[{"value": "arn:aws:iam::123456789098:instance-profile/ip1"}, '
            '{"value": "arn:aws:iam::123456789098:instance-profile/ip2"}]',
            entitlements='[{"value": "allow-cluster-create"}, {"value": "allow-instance-pool-create"}]',
        )
    ]


def test_snapshot_with_group_not_created_in_account_console_should_be_filtered():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(id="1234", display_name="ds")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv").snapshot()
    assert res == []


def test_snapshot_with_group_already_migrated_should_be_filtered():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        display_name="de",
        meta=ResourceMeta(resource_type="Group"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(id="1234", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv").snapshot()
    assert res == []


def test_snapshot_should_filter_account_system_groups():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(id="1234", display_name="account users")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv").snapshot()
    assert res == []


def test_snapshot_should_filter_workspace_system_groups():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(id="1", display_name="admins", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group]
    acc_group = Group(id="1234", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [acc_group]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv").snapshot()
    assert res == []


def test_snapshot_should_consider_groups_defined_in_conf():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    group2 = Group(id="2", display_name="ds", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1, group2]
    acc_group_1 = Group(id="11", display_name="de", external_id="1234")
    acc_group_2 = Group(id="12", display_name="ds", external_id="1235")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [acc_group_1, acc_group_2]],
    }

    wsclient.groups.list.return_value = [group1, group2]
    wsclient.groups.get.side_effect = [group1, group2]
    res = GroupManager(backend, wsclient, inventory_database="inv", include_group_names=["de"]).snapshot()

    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="de",
            temporary_name="ucx-renamed-de",
            members=None,
            external_id="1234",
            roles=None,
            entitlements=None,
        )
    ]


def test_snapshot_should_filter_system_groups_defined_in_conf():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    acc_group_1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [acc_group_1]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv", include_group_names=["admins"]).snapshot()
    assert res == []


def test_snapshot_should_filter_groups_defined_in_conf_not_present_in_workspace():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="ds", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    acc_group_1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [acc_group_1]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv", include_group_names=["de"]).snapshot()
    assert res == []


def test_snapshot_should_filter_groups_defined_in_conf_not_present_in_account():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    acc_group_1 = Group(id="11", display_name="ds")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [acc_group_1]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv", include_group_names=["de"]).snapshot()
    assert res == []


def test_snapshot_should_rename_groups_defined_in_conf():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    group2 = Group(id="2", display_name="ds", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    account_admins_group_1 = Group(id="11", display_name="de")
    account_admins_group_2 = Group(id="12", display_name="ds")
    wsclient.groups.list.return_value = [group1, group2]
    account_admins_group_1 = Group(id="11", display_name="de", external_id="1234")
    account_admins_group_2 = Group(id="12", display_name="ds", external_id="1235")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group_1, account_admins_group_2]],
    }

    wsclient.groups.list.return_value = [group1, group2]
    wsclient.groups.get.side_effect = [group1, group2]
    gm = GroupManager(backend, wsclient, inventory_database="inv", renamed_group_prefix="test-group-")
    res = gm.snapshot()

    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="de",
            temporary_name="test-group-de",
            members=None,
            external_id="1234",
            roles=None,
            entitlements=None,
        ),
        MigratedGroup(
            id_in_workspace="2",
            name_in_workspace="ds",
            name_in_account="ds",
            temporary_name="test-group-ds",
            members=None,
            external_id="1235",
            roles=None,
            entitlements=None,
        ),
    ]


def test_rename_groups_should_patch_eligible_groups():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [
        group1,
    ]
    wsclient.groups.get.return_value = group1
    account_admins_group_1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group_1]],
    }
    GroupManager(backend, wsclient, inventory_database="inv", renamed_group_prefix="test-group-").rename_groups()
    wsclient.groups.patch.assert_called_with(
        "1",
        operations=[iam.Patch(iam.PatchOp.REPLACE, "displayName", "test-group-de")],
    )


def test_rename_groups_should_filter_account_groups_in_workspace():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [group1]
    account_group1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_group1]],
    }
    GroupManager(backend, wsclient, inventory_database="inv").rename_groups()
    wsclient.groups.patch.assert_not_called()


def test_rename_groups_should_filter_already_renamed_groups():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="test-group-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    wsclient.groups.get.return_value = group1
    GroupManager(backend, wsclient, inventory_database="inv", renamed_group_prefix="test-group-").rename_groups()
    wsclient.groups.patch.assert_not_called()


def test_rename_groups_should_fail_if_error_is_thrown():
    backend = MockBackend()
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [
        group1,
    ]
    wsclient.groups.get.return_value = group1
    account_admins_group_1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group_1]],
    }
    wsclient.groups.patch.side_effect = RuntimeError("Something bad")
    gm = GroupManager(backend, wsclient, inventory_database="inv", renamed_group_prefix="test-group-")
    with pytest.raises(ManyError) as e:
        gm.rename_groups()
    assert e.value.args[0] == "Detected 1 failures: RuntimeError: Something bad"


def test_reflect_account_groups_on_workspace_should_be_called_for_eligible_groups():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    account_group = Group(id="1", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_group]],
    }

    group1 = Group(id="1", display_name="test-dfd-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    wsclient.groups.get.return_value = group1
    (GroupManager(backend, wsclient, inventory_database="inv").reflect_account_groups_on_workspace())

    wsclient.api_client.do.assert_called_with(
        "PUT", "/api/2.0/preview/permissionassignments/principals/1", data='{"permissions": ["USER"]}'
    )


def test_reflect_account_groups_on_workspace_should_filter_account_groups_in_workspace():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [group1]
    wsclient.groups.get.return_value = group1
    account_group1 = Group(id="11", display_name="de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_group1]],
    }
    GroupManager(backend, wsclient, inventory_database="inv").reflect_account_groups_on_workspace()

    with pytest.raises(AssertionError):
        wsclient.api_client.do.assert_called_with("PUT")


def test_reflect_account_groups_on_workspace_should_filter_account_groups_not_in_account():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    group1 = Group(id="1", display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    wsclient.groups.get.return_value = group1
    account_group1 = Group(id="11", display_name="ds")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_group1]],
    }
    GroupManager(backend, wsclient, inventory_database="inv").reflect_account_groups_on_workspace()

    with pytest.raises(AssertionError):
        wsclient.api_client.do.assert_called_with("PUT")


def test_reflect_account_should_fail_if_error_is_thrown():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    account_group = Group(id="1", display_name="de")

    def do_side_effect(*args, **kwargs):
        if args[0] == "GET":
            return {"Resources": [g.as_dict() for g in [account_group]]}
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_side_effect

    group1 = Group(id="1", display_name="test-dfd-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1]
    gm = GroupManager(backend, wsclient, inventory_database="inv")

    with pytest.raises(ManyError):
        gm.reflect_account_groups_on_workspace()


def test_reflect_account_should_not_fail_if_group_not_in_the_account_anymore():
    backend = MockBackend(rows={"SELECT": [("1", "de", "de", "test-group-de", "", "", "", "")]})
    wsclient = MagicMock()
    account_group1 = Group(id="11", display_name="de")

    def reflect_account_side_effect(method, *args, **kwargs):
        if method == "GET":
            return {
                "Resources": [g.as_dict() for g in [account_group1]],
            }
        if method == "PUT":
            raise ResourceDoesNotExist(
                "The group has been removed from the Databricks account after getting the group "
                "and before reflecting it to the workspace."
            )

    wsclient.api_client.do.side_effect = reflect_account_side_effect
    GroupManager(backend, wsclient, inventory_database="inv").reflect_account_groups_on_workspace()

    wsclient.api_client.do.assert_called_with(
        "PUT",
        f"/api/2.0/preview/permissionassignments/principals/{account_group1.id}",
        data=json.dumps({"permissions": ["USER"]}),
    )


def test_delete_original_workspace_groups_should_delete_relected_acc_groups_in_workspace():
    account_id = "11"
    ws_id = "1"
    backend = MockBackend(rows={"SELECT": [(ws_id, "de", "de", "test-group-de", account_id, "", "", "")]})
    wsclient = MagicMock()

    temp_group = Group(id=ws_id, display_name="test-group-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    reflected_group = Group(id=account_id, display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [temp_group, reflected_group]
    wsclient.groups.get.return_value = temp_group
    GroupManager(backend, wsclient, inventory_database="inv").delete_original_workspace_groups()
    wsclient.groups.delete.assert_called_with(id=ws_id)


def test_delete_original_workspace_groups_should_not_delete_groups_not_renamed():
    account_id = "11"
    ws_id = "1"
    backend = MockBackend(rows={"SELECT": [(ws_id, "de", "de", "test-group-de", account_id, "", "", "")]})
    wsclient = MagicMock()

    temp_group = Group(id=ws_id, display_name="de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    reflected_group = Group(id=account_id, display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [temp_group, reflected_group]
    wsclient.groups.get.return_value = temp_group
    GroupManager(backend, wsclient, inventory_database="inv").delete_original_workspace_groups()
    wsclient.groups.delete.assert_not_called()


def test_delete_original_workspace_groups_should_not_delete_groups_not_reflected_to_workspace():
    account_id = "11"
    ws_id = "1"
    backend = MockBackend(rows={"SELECT": [(ws_id, "de", "de", "test-group-de", account_id, "", "", "")]})
    wsclient = MagicMock()

    temp_group = Group(id=ws_id, display_name="test-group-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [temp_group]
    wsclient.groups.get.return_value = temp_group
    GroupManager(backend, wsclient, inventory_database="inv").delete_original_workspace_groups()
    wsclient.groups.delete.assert_not_called()


def test_delete_original_workspace_groups_should_not_fail_if_target_group_doesnt_exist():
    account_id = "11"
    ws_id = "1"
    backend = MockBackend(rows={"SELECT": [(ws_id, "de", "de", "test-group-de", account_id, "", "", "")]})
    wsclient = MagicMock()

    temp_group = Group(id=ws_id, display_name="test-group-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    reflected_group = Group(id=account_id, display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [temp_group, reflected_group]

    wsclient.groups.delete.side_effect = DatabricksError(message="None Group with id 100 not found")
    gm = GroupManager(backend, wsclient, inventory_database="inv")

    try:
        gm.delete_original_workspace_groups()
    except DatabricksError:
        fail("delete_original_workspace_groups() raised DatabricksError unexpectedly!")


def test_delete_original_workspace_groups_should_fail_if_delete_does_not_work():
    account_id = "11"
    ws_id = "1"
    backend = MockBackend(rows={"SELECT": [(ws_id, "de", "de", "test-group-de", account_id, "", "", "")]})
    wsclient = MagicMock()

    temp_group = Group(id=ws_id, display_name="test-group-de", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    reflected_group = Group(id=account_id, display_name="de", meta=ResourceMeta(resource_type="Group"))
    wsclient.groups.list.return_value = [temp_group, reflected_group]
    wsclient.groups.get.return_value = temp_group

    wsclient.groups.delete.side_effect = RuntimeError("Something bad")
    gm = GroupManager(backend, wsclient, inventory_database="inv")

    with pytest.raises(ManyError):
        gm.delete_original_workspace_groups()


def test_list_workspace_groups():
    backend = MockBackend()
    wsclient = MagicMock()

    # Mock the groups.list method to return a list of groups
    group1 = Group(id="1", display_name="group_1", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    group2 = Group(id="2", display_name="group_2", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    group3 = Group(id="3", display_name="group_3", meta=ResourceMeta(resource_type="WorkspaceGroup"))
    wsclient.groups.list.return_value = [group1, group2, group3]

    # Mock the _safe_get_group method to return a group
    full_group1 = Group(
        id="1",
        display_name="group_1",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    full_group2 = Group(
        id="2",
        display_name="group_2",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    full_group3 = Group(
        id="3",
        display_name="group_3",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )

    def my_side_effect(group_id, **kwargs):
        if group_id == "1":
            return full_group1
        elif group_id == "2":
            return full_group2
        elif group_id == "3":
            return full_group3

    wsclient.groups.get.side_effect = my_side_effect

    # Test when attributes do not contain "members"
    gm = GroupManager(backend, wsclient, inventory_database="inv")
    result = gm._list_workspace_groups("WorkspaceGroup", "id,displayName,meta")
    assert len(result) == 3
    assert result[0].display_name == "group_1"
    assert result[0].members is None
    wsclient.groups.get.assert_not_called()

    # Test when attributes contain "members"
    result = gm._list_workspace_groups("WorkspaceGroup", "id,displayName,meta,members")
    assert len(result) == 3
    assert result[0].display_name == "group_1"
    assert result[0].members == [
        ComplexValue(display="test-user-1", value="20"),
        ComplexValue(display="test-user-2", value="21"),
    ]
    wsclient.groups.get.assert_called()


def test_snapshot_with_group_matched_by_suffix():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(id="1234", external_id="1234", display_name="de_sx")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex="$", workspace_group_replace="_sx"
    ).snapshot()
    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="de_sx",
            temporary_name="ucx-renamed-de",
            members='[{"display": "test-user-1", "value": "20"}, {"display": "test-user-2", "value": "21"}]',
            external_id="1234",
            roles='[{"value": "arn:aws:iam::123456789098:instance-profile/ip1"}, '
            '{"value": "arn:aws:iam::123456789098:instance-profile/ip2"}]',
            entitlements='[{"value": "allow-cluster-create"}, {"value": "allow-instance-pool-create"}]',
        )
    ]


def test_snapshot_with_group_matched_by_prefix():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(id="1234", external_id="1234", display_name="px_de")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex="^", workspace_group_replace="px_"
    ).snapshot()
    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="px_de",
            temporary_name="ucx-renamed-de",
            members='[{"display": "test-user-1", "value": "20"}, {"display": "test-user-2", "value": "21"}]',
            external_id="1234",
            roles='[{"value": "arn:aws:iam::123456789098:instance-profile/ip1"}, '
            '{"value": "arn:aws:iam::123456789098:instance-profile/ip2"}]',
            entitlements='[{"value": "allow-cluster-create"}, {"value": "allow-instance-pool-create"}]',
        )
    ]


def test_snapshot_with_group_matched_by_subset():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="de_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(id="1234", external_id="1234", display_name="px_1234")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).snapshot()
    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de_(1234)",
            name_in_account="px_1234",
            temporary_name="ucx-renamed-de_(1234)",
            members='[{"display": "test-user-1", "value": "20"}, {"display": "test-user-2", "value": "21"}]',
            external_id="1234",
            roles='[{"value": "arn:aws:iam::123456789098:instance-profile/ip1"}, '
            '{"value": "arn:aws:iam::123456789098:instance-profile/ip2"}]',
            entitlements='[{"value": "allow-cluster-create"}, {"value": "allow-instance-pool-create"}]',
        )
    ]


def test_snapshot_with_group_matched_by_external_id():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="de",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="20"), ComplexValue(display="test-user-2", value="21")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(id="1234", external_id="1234", display_name="xxxx")
    wsclient.api_client.do.return_value = {
        "Resources": [g.as_dict() for g in [account_admins_group]],
    }
    res = GroupManager(backend, wsclient, inventory_database="inv", external_id_match=True).snapshot()
    assert res == [
        MigratedGroup(
            id_in_workspace="1",
            name_in_workspace="de",
            name_in_account="xxxx",
            temporary_name="ucx-renamed-de",
            members='[{"display": "test-user-1", "value": "20"}, {"display": "test-user-2", "value": "21"}]',
            external_id="1234",
            roles='[{"value": "arn:aws:iam::123456789098:instance-profile/ip1"}, '
            '{"value": "arn:aws:iam::123456789098:instance-profile/ip2"}]',
            entitlements='[{"value": "allow-cluster-create"}, {"value": "allow-instance-pool-create"}]',
        )
    ]


def test_configure_include_groups():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "0",  # name match
                r"^Comma-separated list of workspace group names to migrate.*": "foo, bar,  baz",
            }
        )
    )
    cg.run()
    assert ["foo", "bar", "baz"] == cg.include_group_names


def test_configure_prefix():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "1",  # prefix
                r".*prefix.*": "test",
                ".*": "",
            }
        )
    )
    cg.run()
    assert "^" == cg.workspace_group_regex
    assert "test" == cg.workspace_group_replace


def test_configure_suffix():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "2",  # suffix
                r".*suffix.*": "test",
                ".*": "",
            }
        )
    )
    cg.run()
    assert "$" == cg.workspace_group_regex
    assert "test" == cg.workspace_group_replace


def test_configure_external_id():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "3",  # external id
                ".*": "",
            }
        )
    )
    cg.run()
    assert cg.group_match_by_external_id


def test_configure_substitute():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "4",  # substitute
                r".*for substitution": "biz",
                r".*substitution value": "business",
                ".*": "",
            }
        )
    )
    cg.run()
    assert "biz" == cg.workspace_group_regex
    assert "business" == cg.workspace_group_replace


def test_configure_match():
    cg = ConfigureGroups(
        MockPrompts(
            {
                "Backup prefix": "",
                r"Choose how to map the workspace groups.*": "5",  # partial match
                r".*match on the workspace.*": r"\[(#+)\]",
                r".*match on the account.*": r"\((#+)\)",
                ".*": "",
            }
        )
    )
    cg.run()
    assert r"\[(#+)\]" == cg.workspace_group_regex
    assert r"\((#+)\)" == cg.account_group_regex


def test_state():
    groups = [
        MigratedGroup(
            id_in_workspace="1", name_in_workspace="test1", name_in_account="acc_test1", temporary_name="db-temp-test1"
        )
    ]

    state = MigrationState(groups)

    assert state.get_target_principal("test1") == "acc_test1"
    assert state.get_temp_principal("test1") == "db-temp-test1"
    assert state.is_in_scope("test1")

    assert not state.get_target_principal("invalid_group_name")
    assert not state.get_temp_principal("invalid_group_name")
    assert not state.is_in_scope("invalid_group_name")


def test_validate_group_diff_membership():
    backend = create_autospec(SqlBackend)
    wsclient = create_autospec(WorkspaceClient)
    group = Group(
        id="1",
        external_id="1234",
        display_name="test_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="1"), ComplexValue(display="test-user-2", value="2")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(
        id="1234",
        external_id="1234",
        display_name="ac_test_1234",
        members=[ComplexValue(display="test-user-3", value="3")],
    )

    def do_api_side_effect(*args, **kwargs):
        if args[0] == "GET":
            if args[1] == "/api/2.0/account/scim/v2/Groups":
                return {"Resources": [g.as_dict() for g in [account_admins_group]]}
            else:
                return account_admins_group.as_dict()
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_api_side_effect
    wsclient.groups.get.side_effect = lambda group_id: group if group_id == "1" else account_admins_group
    grp_membership = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).validate_group_membership()
    assert grp_membership == [
        {
            "wf_group_name": "test_(1234)",
            "wf_group_members_count": 2,
            "acc_group_name": "ac_test_1234",
            "acc_group_members_count": 1,
        }
    ]


def test_validate_group_diff_membership_no_members():
    backend = create_autospec(SqlBackend)
    wsclient = create_autospec(WorkspaceClient)
    group = Group(
        id="1",
        external_id="1234",
        display_name="test_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=None,
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(
        id="1234",
        external_id="1234",
        display_name="ac_test_1234",
        members=None,
    )

    def do_api_side_effect(*args, **kwargs):
        if args[0] == "GET":
            if args[1] == "/api/2.0/account/scim/v2/Groups":
                return {"Resources": [g.as_dict() for g in [account_admins_group]]}
            else:
                return account_admins_group.as_dict()
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_api_side_effect
    wsclient.groups.get.side_effect = lambda group_id: group if group_id == "1" else account_admins_group
    grp_membership = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).validate_group_membership()
    assert grp_membership == []


def test_validate_group_diff_membership_no_account_group_found():
    backend = create_autospec(SqlBackend)
    wsclient = create_autospec(WorkspaceClient)
    group = Group(
        id="1",
        external_id="1234",
        display_name="test_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=None,
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/ip1"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    account_admins_group = Group(
        id="1234",
        external_id="1234",
        display_name="ac_test_1234",
        members=None,
    )

    def do_api_side_effect(*args, **kwargs):
        if args[0] == "GET":
            if args[1] == "/api/2.0/account/scim/v2/Groups":
                return {"Resources": [g.as_dict() for g in [account_admins_group]]}
            else:
                return account_admins_group.as_dict()
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_api_side_effect
    wsclient.groups.get.side_effect = lambda group_id: group if group_id == "1" else None
    grp_membership = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).validate_group_membership()
    assert grp_membership == []


def test_validate_group_same_membership():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="test_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="01"), ComplexValue(display="test-user-2", value="02")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/test_ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/test_ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(
        id="1234",
        external_id="1234",
        display_name="ac_test_1234",
        members=[ComplexValue(display="test-user-1", value="01"), ComplexValue(display="test-user-2", value="02")],
    )

    def do_api_side_effect(*args, **kwargs):
        if args[0] == "GET":
            if args[1] == "/api/2.0/account/scim/v2/Groups":
                return {"Resources": [g.as_dict() for g in [account_admins_group]]}
            else:
                return account_admins_group.as_dict()
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_api_side_effect
    grp_membership = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).validate_group_membership()
    assert grp_membership == []


def test_validate_acc_group_removed_after_listing():
    backend = MockBackend()
    wsclient = MagicMock()
    group = Group(
        id="1",
        external_id="1234",
        display_name="test_(1234)",
        meta=ResourceMeta(resource_type="WorkspaceGroup"),
        members=[ComplexValue(display="test-user-1", value="01"), ComplexValue(display="test-user-2", value="02")],
        roles=[
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/test_ip1"),
            ComplexValue(value="arn:aws:iam::123456789098:instance-profile/test_ip2"),
        ],
        entitlements=[ComplexValue(value="allow-cluster-create"), ComplexValue(value="allow-instance-pool-create")],
    )
    wsclient.groups.list.return_value = [group]
    wsclient.groups.get.return_value = group
    account_admins_group = Group(
        id="1234",
        external_id="1234",
        display_name="ac_test_1234",
        members=[ComplexValue(display="test-user-1", value="01"), ComplexValue(display="test-user-2", value="02")],
    )

    def do_api_side_effect(*args, **kwargs):
        if args[0] == "GET":
            if args[1] == "/api/2.0/account/scim/v2/Groups":
                return {"Resources": [g.as_dict() for g in [account_admins_group]]}
            else:
                raise NotFound()
        else:
            raise RuntimeError()

    wsclient.api_client.do.side_effect = do_api_side_effect
    grp_membership = GroupManager(
        backend, wsclient, inventory_database="inv", workspace_group_regex=r"\(([1-9]+)\)", account_group_regex="[1-9]+"
    ).validate_group_membership()
    assert grp_membership == []
