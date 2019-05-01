# Copyright 2018 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.from c7n_azure.provider import resources

import logging
import enum
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager, ChildArmResourceManager
from c7n_azure.query import ChildResourceQuery
from c7n_azure.filters import scalar_ops
from c7n.filters import Filter
from c7n.filters.core import PolicyValidationError
from c7n_azure.utils import RetentionPeriod, ResourceIdParser, ThreadHelper
from c7n_azure.actions import AzureBaseAction
from c7n.utils import type_schema
from msrestazure.azure_exceptions import CloudError

log = logging.getLogger('custodian.azure.sqldatabase')


@resources.register('sqldatabase')
class SqlDatabase(ChildArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.sql'
        client = 'SqlManagementClient'
        enum_spec = ('databases', 'list_by_server', {
            'resource_group_name': 'resourceGroup',
            'server_name': 'name'
        })
        parent_spec = ChildArmResourceManager.ParentSpec(
            manager_name='sqlserver',
            annotate_parent=True
        )


class BackupRetentionPolicyHelper(object):

    SHORT_TERM_SQL_OPERATIONS = 'backup_short_term_retention_policies'
    LONG_TERM_SQL_OPERATIONS = 'backup_long_term_retention_policies'

    @enum.unique
    class LongTermBackupType(enum.Enum):
        weekly = 'weekly'
        monthly = 'monthly'
        yearly = 'yearly'

        def __str__(self):
            return self.value

    @staticmethod
    def get_backup_retention_policy_context(i):
        resource_group_name = i['resourceGroup']
        server_id = i[ChildResourceQuery.parent_key]
        database_name = i['name']
        server_name = ResourceIdParser.get_resource_name(server_id)
        if server_name is None:
            raise ValueError("Unable to determine the sqlserver name for sqldatabase")
        return resource_group_name, server_name, database_name


class BackupRetentionPolicyFilter(Filter):

    schema = type_schema(
        'backup-retention-policy',
        **{
            'op': {'enum': list(scalar_ops.keys())}
        }
    )

    def __init__(self, operations_property, retention_limit, data, manager=None):
        super(BackupRetentionPolicyFilter, self).__init__(data, manager)
        self.operations_property = operations_property
        self.retention_limit = retention_limit

    def get_retention_from_policy(self, retention_policy):
        raise NotImplementedError()

    def process(self, resources, event=None):
        resources, exceptions = ThreadHelper.execute_in_parallel(
            resources=resources,
            event=event,
            execution_method=self._process_resource_set,
            executor_factory=self.executor_factory,
            log=log
        )
        if exceptions:
            raise exceptions[0]
        return resources

    def _process_resource_set(self, resources, event):
        client = self.manager.get_client()
        get_operation = getattr(client, self.operations_property).get
        matched_resources = []

        for resource in resources:
            match = self._process_resource(resource, get_operation)
            if match:
                matched_resources.append(resource)
        return matched_resources

    def _process_resource(self, i, get_operation):
        retention_policy = self._get_backup_retention_policy(i, get_operation)
        if retention_policy is None:
            return self._perform_op(0, self.retention_limit)
        retention = self.get_retention_from_policy(retention_policy)
        return retention is not None and self._perform_op(retention, self.retention_limit)

    def _get_backup_retention_policy(self, i, get_operation):
        resource_group_name, server_name, database_name = \
            BackupRetentionPolicyHelper.get_backup_retention_policy_context(i)

        try:
            response = get_operation(resource_group_name, server_name, database_name)
        except CloudError as e:
            if e.status_code == 404:
                response = None
            else:
                log.error("Unable to get backup retention policy. "
                "(resourceGroup: {}, sqlserver: {}, sqldatabase: {})".format(
                    resource_group_name, server_name, database_name))
                raise e

        return response

    def _perform_op(self, a, b):
        op = scalar_ops.get(self.data.get('op', 'eq'))
        return op(a, b)


@SqlDatabase.filter_registry.register('short-term-backup-retention-policy')
class ShortTermBackupRetentionPolicyFilter(BackupRetentionPolicyFilter):
    """

    Filter SQL Databases on the length of their short term backup retention policies.

    If the database has no backup retention policies, the database is treated as if
    it has a backup retention of zero days.

    :example: Find all SQL Databases with a short term retention policy shorter than 2 weeks.

    .. code-block:: yaml

            policies:
              - name: short-term-backup-retention-policy
                resource: azure.sqldatabase
                filters:
                  - type: short-term-backup-retention-policy
                    op: lt
                    retention-period-days: 14

    """

    schema = type_schema(
        'short-term-backup-retention-policy',
        required=['retention-period-days'],
        rinherit=BackupRetentionPolicyFilter.schema,
        **{
            'retention-period-days': {'type': 'number'}
        }
    )

    def __init__(self, data, manager=None):
        retention_limit = data.get('retention-period-days')
        super(ShortTermBackupRetentionPolicyFilter, self).__init__(
            BackupRetentionPolicyHelper.SHORT_TERM_SQL_OPERATIONS, retention_limit, data, manager)

    def get_retention_from_policy(self, retention_policy):
        return retention_policy.retention_days


@SqlDatabase.filter_registry.register('long-term-backup-retention-policy')
class LongTermBackupRetentionPolicyFilter(BackupRetentionPolicyFilter):
    """

    Filter SQL Databases on the length of their long term backup retention policies.

    There are 3 backup types for a sql database: weekly, monthly, and yearly. And, each
    of these backups has a retention period that can specified in units of days, weeks,
    months, or years.

    :example: Find all SQL Databases with weekly backup retentions longer than 1 month.

    .. code-block:: yaml

            policies:
              - name: long-term-backup-retention-policy
                resource: azure.sqldatabase
                filters:
                  - type: long-term-backup-retention-policy
                    backup-type: weekly
                    op: gt
                    retention-period: 1
                    retention-period-units: months

    """

    schema = type_schema(
        'long-term-backup-retention-policy',
        required=['backup-type', 'retention-period', 'retention-period-units'],
        rinherit=BackupRetentionPolicyFilter.schema,
        **{
            'backup-type': {'enum': list([str(t) for t in
                BackupRetentionPolicyHelper.LongTermBackupType])},
            'retention-period': {'type': 'number'},
            'retention-period-units': {
                'enum': list([str(u) for u in RetentionPeriod.Units])
            }
        }
    )

    def __init__(self, data, manager=None):
        retention_period = data.get('retention-period')
        self.retention_period_units = RetentionPeriod.Units[
            data.get('retention-period-units')]

        super(LongTermBackupRetentionPolicyFilter, self).__init__(
            BackupRetentionPolicyHelper.LONG_TERM_SQL_OPERATIONS, retention_period, data, manager)
        self.backup_type = self.data.get('backup-type')

    def get_retention_from_policy(self, retention_policy):
        if self.backup_type == BackupRetentionPolicyHelper.LongTermBackupType.weekly.value:
            actual_retention_iso8601 = retention_policy.weekly_retention
        elif self.backup_type == BackupRetentionPolicyHelper.LongTermBackupType.monthly.value:
            actual_retention_iso8601 = retention_policy.monthly_retention
        elif self.backup_type == BackupRetentionPolicyHelper.LongTermBackupType.yearly.value:
            actual_retention_iso8601 = retention_policy.yearly_retention
        else:
            raise ValueError("Unknown backup-type: {}".format(self.backup_type))

        try:
            actual_duration, actual_duration_units = RetentionPeriod.parse_iso8601_retention_period(
                actual_retention_iso8601)
        except ValueError:
            return None

        if actual_duration_units.iso8601_symbol != self.retention_period_units.iso8601_symbol:
            return None
        return actual_duration


class BackupRetentionPolicyAction(AzureBaseAction):

    def _process_resource(self, resource, operations_property):
        client = self.manager.get_client()
        update_operation = getattr(client, operations_property).create_or_update

        resource_group_name, server_name, database_name = \
            BackupRetentionPolicyHelper.get_backup_retention_policy_context(resource)
        parameters = self.get_parameters_for_new_retention_policy()

        update_operation(resource_group_name, server_name, database_name, parameters)

    def get_parameters_for_new_retention_policy(self):
        raise NotImplementedError()


@SqlDatabase.action_registry.register('update-short-term-backup-retention-policy')
class ShortTermBackupRetentionPolicyAction(BackupRetentionPolicyAction):

    VALID_RETENTION_PERIOD_DAYS = [7, 14, 21, 28, 35]

    schema = type_schema('update-short-term-backup-retention-policy',
                         rinherit=ShortTermBackupRetentionPolicyFilter.schema,
                         op=None)

    def __init__(self, data=None, manager=None, log_dir=None):
        super(ShortTermBackupRetentionPolicyAction, self).__init__(data, manager, log_dir)
        self.retention_period_days = self.data['retention-period-days']

    def _process_resource(self, resource):
        super(ShortTermBackupRetentionPolicyAction, self)._process_resource(
            resource, BackupRetentionPolicyHelper.SHORT_TERM_SQL_OPERATIONS)

    def get_parameters_for_new_retention_policy(self):
        return self.retention_period_days

    def validate(self):
        if self.retention_period_days not in \
                ShortTermBackupRetentionPolicyAction.VALID_RETENTION_PERIOD_DAYS:
            raise PolicyValidationError(
                "Invalid retention-period-days: {}. Valid values are: {}".format(
                    self.retention_period_days,
                    ShortTermBackupRetentionPolicyAction.VALID_RETENTION_PERIOD_DAYS
                )
            )
        return self


@SqlDatabase.action_registry.register('update-long-term-backup-retention-policy')
class LongTermBackupRetentionPolicyAction(BackupRetentionPolicyAction):

    schema = type_schema('update-long-term-backup-retention-policy',
                         rinherit=LongTermBackupRetentionPolicyFilter.schema,
                         op=None)

    def _process_resource(self, resource):
        super(LongTermBackupRetentionPolicyAction, self)._process_resource(
            resource, BackupRetentionPolicyHelper.LONG_TERM_SQL_OPERATIONS)

    def get_parameters_for_new_retention_policy(self):
        retention_period = self.data['retention-period']
        retention_period_units = RetentionPeriod.Units[self.data['retention-period-units']]
        iso8601_duration = RetentionPeriod.iso8601_duration_from_period_and_units(
            retention_period, retention_period_units)

        backup_type = self.data['backup-type']
        weekly_retention = iso8601_duration if \
            backup_type == BackupRetentionPolicyHelper.LongTermBackupType.weekly.value else None
        monthly_retention = iso8601_duration if \
            backup_type == BackupRetentionPolicyHelper.LongTermBackupType.monthly.value else None
        yearly_retention = iso8601_duration if \
            backup_type == BackupRetentionPolicyHelper.LongTermBackupType.monthly.yearly else None

        # TODO: when only one value is specified, the ones that aren't are cleared.
        # we should either require that all are specified, or lookup the existing
        # values and set the unspecified ones to their current values.
        return {
            'weekly_retention': weekly_retention,
            'monthly_retention': monthly_retention,
            'yearly_retention': yearly_retention
        }
