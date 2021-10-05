import logging
import os
import unittest
from unittest import mock

from secret_manager import SecretManager

logging.getLogger().setLevel(logging.CRITICAL)

MASTER_KEY = 'test'
SECRET_FILE = './test_secret'


class TestAddMethod(unittest.TestCase):

    def setUp(self) -> None:
        self.sm = SecretManager(MASTER_KEY, SECRET_FILE)

    def tearDown(self) -> None:
        if os.path.exists(SECRET_FILE):
            os.remove(SECRET_FILE)

    @mock.patch('secret_manager.getpass', create=True)
    def test_add_correctly(self, mocked_input):
        mocked_input.side_effect = ['secretvalue']
        self.assertIsNone(self.sm.add_secret('test'))

    @mock.patch('secret_manager.getpass', create=True)
    def test_add_already_existing_secret(self, mocked_input):
        mocked_input.side_effect = ['secretvalue']
        self.sm.add_secret('test')
        self.assertEqual(self.sm.add_secret('test'), False)

    @mock.patch('secret_manager.getpass', create=True)
    def test_add_empty_value(self, mocked_input):
        mocked_input.side_effect = ['']
        self.assertIsNone(self.sm.add_secret('test'))

    @mock.patch('secret_manager.getpass', create=True)
    def test_add_very_long_value(self, mocked_input):
        mocked_input.side_effect = ['secretvalue' * 1000]
        self.assertIsNone(self.sm.add_secret('test'))


class TestGetMethod(unittest.TestCase):

    @mock.patch('secret_manager.getpass', create=True)
    def setUp(self, mocked_input) -> None:
        mocked_input.side_effect = ['secretvalue']
        self.sm = SecretManager(MASTER_KEY, SECRET_FILE)
        self.sm.add_secret('test')

    def tearDown(self) -> None:
        if os.path.exists(SECRET_FILE):
            os.remove(SECRET_FILE)

    def test_get_correctly(self):
        self.assertEqual(self.sm.get_secret('test'), 'secretvalue')

    def test_get_non_existent_secret(self):
        self.assertEqual(self.sm.get_secret('nonexistent'), False)


class TestDelMethod(unittest.TestCase):

    def setUp(self) -> None:
        self.sm = SecretManager(MASTER_KEY, SECRET_FILE)

    def tearDown(self) -> None:
        if os.path.exists(SECRET_FILE):
            os.remove(SECRET_FILE)

    @mock.patch('secret_manager.getpass', create=True)
    def test_delete_existing_secret(self, mocked_input):
        mocked_input.side_effect = ['secretvalue']
        self.sm.add_secret('test')
        self.assertIsNone(self.sm.del_secret('test'))

    @mock.patch('secret_manager.getpass', create=True)
    def test_delete_non_existent_secret(self, mocked_input):
        mocked_input.side_effect = ['secretvalue']
        self.sm.add_secret('test')
        self.assertEqual(self.sm.del_secret('nonexistent'), False)

    def test_delete_with_empty_file(self):
        self.assertEqual(self.sm.del_secret('nonexistent'), False)


if __name__ == '__main__':
    unittest.main()
