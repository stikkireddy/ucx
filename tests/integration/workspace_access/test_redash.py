import logging
from datetime import timedelta
from unittest import skip

from databricks.sdk.errors import NotFound
from databricks.sdk.retries import retried
from databricks.sdk.service import iam, sql

from databricks.labs.ucx.workspace_access import redash
from databricks.labs.ucx.workspace_access.groups import MigratedGroup, MigrationState
from databricks.labs.ucx.workspace_access.redash import RedashPermissionsSupport

from . import apply_tasks, apply_tasks_appliers, apply_tasks_crawlers

logger = logging.getLogger(__name__)


@retried(on=[NotFound], timeout=timedelta(minutes=3))
def test_permissions_for_redash(
    ws,
    sql_backend,
    inventory_schema,
    make_ucx_group,
    make_group,
    make_user,
    make_query,
    make_query_permissions,
):
    ws_group = make_group()
    ws_group_temp = make_group()  # simulate temp/backup group
    acc_group = make_group()
    user = make_user()

    query = make_query()
    make_query_permissions(
        object_id=query.id,
        permission_level=sql.PermissionLevel.CAN_EDIT,
        group_name=ws_group.display_name,
        user_name=user.display_name,
    )

    group_to_migrate = MigratedGroup.partial_info(ws_group, acc_group)
    # Note that Redash support replaces all permissions and apply it on the temp/backup group instead of original group.
    # We don't rename the original group as part of this test therefore we need to set the temp group explicitly here.
    group_to_migrate.temporary_name = ws_group_temp.display_name

    redash_permissions = RedashPermissionsSupport(
        ws,
        [redash.Listing(ws.queries.list, sql.ObjectTypePlural.QUERIES)],
    )
    apply_tasks(redash_permissions, [group_to_migrate])

    query_permissions = redash_permissions.load_as_dict(sql.ObjectTypePlural.QUERIES, query.id)
    # Note that we don't validate the original group permissions here because Redash support apply the permissions
    # on the temp/backup group instead of the original group.
    assert sql.PermissionLevel.CAN_EDIT == query_permissions[ws_group_temp.display_name]
    assert sql.PermissionLevel.CAN_EDIT == query_permissions[acc_group.display_name]
    assert sql.PermissionLevel.CAN_EDIT == query_permissions[user.display_name]


# Redash group permissions are cached for up to 10 mins. If a group is renamed, redash permissions api returns
# the old name for some time. Therefore, we need to allow at least 10 mins in the timeout for checking the permissions
# after group rename.
@skip  # skipping as it takes 5-10 mins to execute
@retried(on=[NotFound], timeout=timedelta(minutes=13))
def test_permissions_for_redash_after_group_is_renamed(
    ws,
    sql_backend,
    inventory_schema,
    make_group,
    make_query,
    make_query_permissions,
):
    """
    Redash permissions are cached for up to 10 mins. See: https://databricks.atlassian.net/browse/ES-992619
    Therefore, when a group is renamed, get redash permissions API can return the old group name for some time.
    This test validates that Redash Permissions Support is able to apply and validate permissions correctly
    after rename operation.
    """
    ws_group = make_group()
    acc_group = make_group()

    query = make_query()
    make_query_permissions(
        object_id=query.id,
        permission_level=sql.PermissionLevel.CAN_EDIT,
        group_name=ws_group.display_name,
    )
    redash_permissions = RedashPermissionsSupport(
        ws,
        [redash.Listing(ws.queries.list, sql.ObjectTypePlural.QUERIES)],
    )
    permissions = apply_tasks_crawlers(redash_permissions)

    group_to_migrate = MigratedGroup.partial_info(ws_group, acc_group)

    def rename_group(group: iam.Group, new_group_name: str) -> iam.Group:
        ws.groups.patch(group.id, operations=[iam.Patch(iam.PatchOp.REPLACE, "displayName", new_group_name)])
        group.display_name = new_group_name
        return group

    # simulate creating temp/backup group by renaming the original workspace-local group
    ws_group_a_temp_name = "tmp-" + ws_group.display_name
    ws_group = rename_group(ws_group, ws_group_a_temp_name)

    apply_tasks_appliers(redash_permissions, permissions, MigrationState([group_to_migrate]))

    query_permissions = redash_permissions.load_as_dict(sql.ObjectTypePlural.QUERIES, query.id)
    assert sql.PermissionLevel.CAN_EDIT == query_permissions[ws_group.display_name]
    assert sql.PermissionLevel.CAN_EDIT == query_permissions[acc_group.display_name]
