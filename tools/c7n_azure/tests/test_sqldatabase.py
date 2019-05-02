# Copyright 2015-2018 Capital One Services, LLC
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
# limitations under the License.

import mock
import datetime
from azure_common import BaseTest, arm_template
from c7n_azure.resources.sqldatabase import BackupRetentionPolicyFilter, \
    ShortTermBackupRetentionPolicyAction
from c7n_azure.query import ChildResourceQuery
from c7n.filters.core import PolicyValidationError
from c7n.utils import local_session
from c7n_azure.session import Session


class SqlDatabaseTest(BaseTest):

    def test_sql_database_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-sql-database-schema-validate',
                'resource': 'azure.sqldatabase'
            }, validate=True)
            self.assertTrue(p)

    @arm_template('sqlserver.json')
    def test_get_database_by_name(self):
        p = self.load_policy({
            'name': 'test-get-database-by-name',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'op': 'eq',
                    'value': 'cctestdb'
                }
            ]
        })

        resources = p.run()
        self._assert_found_only_test_database(resources)

    @arm_template('sqlserver.json')
    def test_find_databases_with_premium_sku(self):
        p = self.load_policy({
            'name': 'test-find-databases-with-premium-sku',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'value',
                    'key': 'sku.tier',
                    'op': 'eq',
                    'value': 'Premium'
                }
            ]
        })

        resources = p.run()
        self._assert_found_only_test_database(resources)

    @arm_template('sqlserver.json')
    def _assert_found_only_test_database(self, resources):
        self.assertEqual(len(resources), 1)
        db = resources[0]

        self.assertEqual(db.get('name'), 'cctestdb')


class BackupRetentionPolicyFilterTest(BaseTest):

    def setUp(self):
        super(BackupRetentionPolicyFilterTest, self).setUp()

        self.resouce_group = "test_sqlserver"
        self.parent_key = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
        "test_sqlserver/providers/Microsoft.Sql/servers/cctestsqlserver"
        self.name = "cctestdb"

        manager = mock.Mock()
        self.filter = BackupRetentionPolicyFilter('op-prop', 0, {}, manager)

    def test_raises_key_error_without_resource_group(self):
        with self.assertRaises(KeyError):
            self.filter.process([{
                ChildResourceQuery.parent_key: self.parent_key,
                'name': self.name
            }])

    def test_raises_key_error_without_parent_key(self):
        with self.assertRaises(KeyError):
            self.filter.process([{
                'resourceGroup': self.resouce_group,
                'name': self.name
            }])

    def test_raises_key_error_without_name(self):
        with self.assertRaises(KeyError):
            self.filter.process([{
                'resourceGroup': self.resouce_group,
                ChildResourceQuery.parent_key: self.parent_key
            }])

    def test_raises_value_error_when_cannot_determine_sql_server_name(self):
        with self.assertRaises(ValueError):
            self.filter.process([{
                'resourceGroup': self.resouce_group,
                ChildResourceQuery.parent_key: "invalidResourceId",
                'name': self.name
            }])


class ShortTermBackupRetentionPolicyFilterTest(BaseTest):

    def test_validate_short_term_backup_retention_policy_filter_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'short-term-schema-validate',
                'resource': 'azure.sqldatabase',
                'filters': [
                    {
                        'type': 'short-term-backup-retention-policy',
                        'op': 'gte',
                        'retention-period-days': 60
                    }
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_find_database_with_short_term_retention_at_14_days(self):
        p = self.load_policy({
            'name': 'find-database-with-short-term-retention-at-14-days',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'short-term-backup-retention-policy',
                    'retention-period-days': 14
                }
            ]
        })
        resources = p.run()
        db = next((r for r in resources if r.get('name') == 'cctestdb'), None)
        self.assertIsNotNone(db)
        self.assertEqual(db.get('name'), 'cctestdb')

    def test_filter_database_with_short_term_retention_at_14_days(self):
        p = self.load_policy({
            'name': 'find-database-with-short-term-retention-at-14-days',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'short-term-backup-retention-policy',
                    'op': 'ne',
                    'retention-period-days': 14
                }
            ]
        })
        resources = p.run()
        db = next((r for r in resources if r.get('name') == 'cctestdb'), None)
        self.assertIsNone(db)


class LongTermBackupRetentionPolicyFilterTest(BaseTest):

    def test_validate_long_term_backup_retention_policy_filter_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'long-term-schema-validate',
                'resource': 'azure.sqldatabase',
                'filters': [
                    {
                        'type': 'long-term-backup-retention-policy',
                        'backup-type': 'weekly',
                        'op': 'gt',
                        'retention-period': 1,
                        'retention-period-units': 'year'
                    }
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_find_database_with_weekly_backup_retention_less_than_2_months(self):

        p = self.load_policy({
            'name': 'find-db-with-weekly-backup-retention-less-than-2-months',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'long-term-backup-retention-policy',
                    'backup-type': 'weekly',
                    'op': 'lt',
                    'retention-period': 2,
                    'retention-period-units': 'months',
                }
            ]
        })

        resources = p.run()
        db = next((r for r in resources if r.get('name') == 'cclongtermretentiondb'), None)
        self.assertIsNotNone(db)
        self.assertEqual(db.get('name'), 'cclongtermretentiondb')

    def test_filter_database_with_yearly_backup_retention_more_than_18_months(self):

        p = self.load_policy({
            'name': 'filter-db-with-yearly-backup-retention-more-than-18-months',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'long-term-backup-retention-policy',
                    'backup-type': 'yearly',
                    'op': 'lte',
                    'retention-period': 18,
                    'retention-period-units': 'months'
                }
            ]
        })

        resources = p.run()
        db = next((r for r in resources if r.get('name') == 'cctestdb'), None)
        self.assertIsNone(db)

    def test_find_database_with_long_term_policy_using_filter_or_operator(self):

        p = self.load_policy({
            'name': 'test-find-database-with-long-term-policy-using-filter-or-operator',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'or': [
                        {
                            'type': 'long-term-backup-retention-policy',
                            'backup-type': 'monthly',
                            'op': 'gte',
                            'retention-period': 12,
                            'retention-period-units': 'months'
                        },
                        {
                            'type': 'long-term-backup-retention-policy',
                            'backup-type': 'monthly',
                            'op': 'gte',
                            'retention-period': 1,
                            'retention-period-units': 'year'
                        },
                    ]
                }
            ]
        })

        resources = p.run()
        db = next((r for r in resources if r.get('name') == 'cclongtermretentiondb'), None)
        self.assertIsNotNone(db)
        self.assertEqual(db.get('name'), 'cclongtermretentiondb')

    def test_filter_database_with_retention_period_unit_mismatch(self):

        p = self.load_policy({
            'name': 'test-filter-database-with-retention-period-unit-mismatch',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'long-term-backup-retention-policy',
                    'backup-type': 'weekly',
                    'op': 'eq',
                    'retention-period': 2,
                    'retention-period-units': 'weeks'
                }
            ]
        })

        resources = p.run()
        self.assertEqual(len(resources), 0)


class ShortTermBackupRetentionPolicyActionSchemaTest(BaseTest):

    def test_validate_short_term_backup_retention_policy_action_schema(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'short-term-action-schema-validate',
                'resource': 'azure.sqldatabase',
                'actions': [
                    {
                        'type': 'update-short-term-backup-retention-policy',
                        'retention-period-days': 14
                    }
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_short_term_backup_retention_policy_action_schema_invalid_retention_period_days(self):
        with self.assertRaises(PolicyValidationError) as context:
            with self.sign_out_patch():
                self.load_policy({
                    'name': 'short-term-action-schema-validate',
                    'resource': 'azure.sqldatabase',
                    'actions': [
                        {
                            'type': 'update-short-term-backup-retention-policy',
                            'retention-period-days': 9
                        }
                    ]
                }, validate=True)
        error_string = str(context.exception)

        self.assertIn("Invalid retention-period-days", error_string)
        self.assertIn("9", error_string)
        self.assertIn(
            str(ShortTermBackupRetentionPolicyAction.VALID_RETENTION_PERIOD_DAYS), error_string)


class ShortTermBackupRetentionPolicyActionTest(BaseTest):

    @classmethod
    def setUpClass(cls, *args, **kwargs):
        super(ShortTermBackupRetentionPolicyActionTest, cls).setUpClass(*args, **kwargs)
        cls.client = local_session(Session).client('azure.mgmt.sql.SqlManagementClient') \
            .backup_short_term_retention_policies
        cls.backup_retention_policy_context = [
            "test_sqlserver", "cctestsqlserverkonu36uvuesr4", "cctestdb"]

    def tearDown(self, *args, **kwargs):
        super(ShortTermBackupRetentionPolicyActionTest, self).tearDown(*args, **kwargs)
        start = datetime.datetime.now()
        poller = ShortTermBackupRetentionPolicyActionTest.client.update(
            *ShortTermBackupRetentionPolicyActionTest.backup_retention_policy_context, 14)
        result = poller.result(timeout=100)
        status = poller.status()
        end = datetime.datetime.now()
        delta_seconds = (end - start).total_seconds()

        self.assertEqual(status, 'Success')
        self.assertEqual(result.retention_period_days, 14)

    @arm_template('sqlserver.json')
    def test_set_short_term_retention_to_28_days(self):
        p = self.load_policy({
            'name': 'test-set-short-term-retention-to-28-days',
            'resource': 'azure.sqldatabase',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'op': 'eq',
                    'value': 'cctestdb'
                }
            ],
            'actions': [
                {
                    'type': 'update-short-term-backup-retention-policy',
                    'retention-period-days': 28
                }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self._assert_retention_period_equal(28)

    def _assert_retention_period_equal(self, days, msg=None):
        current_retention_period = ShortTermBackupRetentionPolicyActionTest.client.get(
            *ShortTermBackupRetentionPolicyActionTest.backup_retention_policy_context)
        self.assertEqual(current_retention_period.retention_days, days, msg)


class LongTermBackupRetentionPolicyActionTest(BaseTest):

    def test_validate_long_term_backup_retention_policy_action_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'long-term-action-schema-validate',
                'resource': 'azure.sqldatabase',
                'actions': [
                    {
                        'type': 'update-long-term-backup-retention-policy',
                        'backup-type': 'yearly',
                        'retention-period': 18,
                        'retention-period-units': 'months'
                    }
                ]
            }, validate=True)
            self.assertTrue(p)

    def test_set_weekly_backup_retention_to_10_days(self):
        p = self.load_policy({
            'name': 'test-set-weekly-backup-retention-to-10-days',
            'resource': 'azure.sqldatabase',
            'actions': [
                {
                    'type': 'update-long-term-backup-retention-policy',
                    'backup-type': 'weekly',
                    'retention-period': 10,
                    'retention-period-units': 'days'
                }
            ]
        })
        self.assertTrue(False, "not implemented")

    def test_set_monthly_backup_retention_to_6_weeks(self):
        p = self.load_policy({
            'name': 'test-set-monthly-backup-retention-to-6-weeks',
            'resource': 'azure.sqldatabase',
            'actions': [
                {
                    'type': 'update-long-term-backup-retention-policy',
                    'backup-type': 'weekly',
                    'retention-period': 10,
                    'retention-period-units': 'days'
                }
            ]
        })
        self.assertTrue(False, "not implemented")

    def test_set_yearly_backup_retention_to_18_months(self):
        p = self.load_policy({
            'name': 'test-set-yearly-backup-retention-to-18-months',
            'resource': 'azure.sqldatabase',
            'actions': [
                {
                    'type': 'update-long-term-backup-retention-policy',
                    'backup-type': 'weekly',
                    'retention-period': 10,
                    'retention-period-units': 'days'
                }
            ]
        })
        self.assertTrue(False, "not implemented")
