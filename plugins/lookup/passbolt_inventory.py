from __future__ import absolute_import, division, print_function
import string
import secrets
import json
from os import environ
from passbolt import PassboltAPI
from ansible.utils.display import Display
from ansible.module_utils._text import to_text
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError, AnsibleParserError

__metaclass__ = type

DOCUMENTATION = """
    name: passbolt_inventory
    author: Copied from passbolt.py
    short_description: retrieve resources and secrets from passbolt API
    description:
        - This lookup returns resources and secrets from passbolt API.
"""

EXAMPLES = """
- hosts: localhost
  gather_facts: no
  tasks:
  - debug:
      msg: "{{ lookup('anatomicjc.passbolt.passbolt_inventory') }}"
"""

RETURN = """
  _raw:
    description:
      - content of file(s)
    type: list
    elements: str
"""


display = Display()


class LookupModule(LookupBase):
    def _get_value(
        self, selected_variable, variables, environment_variables, default=str()
    ):
        variable = variables.get(selected_variable, None)
        if variable is None:
            return self._get_env_value(
                selected_variable=selected_variable,
                environment_variables=environment_variables,
                default=default,
            )
        else:
            return variable

    def _get_env_value(self, selected_variable, environment_variables, default=str()):
        os_environ_variable = environ.get(selected_variable, None)
        if os_environ_variable is not None:
            default = os_environ_variable
        
        return self._templar.template(
            next(
                (
                    item.get(selected_variable)
                    for item in environment_variables
                    if item.get(selected_variable)
                ),
                default,
            )
        )

    def _format_result(self, resource, resource_secrets):
        return {
            "name": resource.get("name", ""),
            "uri": resource.get("uri", ""),
            "username": resource.get("username", ""),
            "password": resource_secrets.get("password", ""),
            "description": resource_secrets.get("description", ""),
            "deleted": resource.get("deleted", ""),
            "created": resource.get("created", ""),
            "modified": resource.get("modified", ""),
            "modified_by": resource.get("modified_by", ""),
            "resource_type_id": resource.get("resource_type_id", ""),
            "forder_parent_id": resource.get("folder_parent_id", ""),
            "personal": resource.get("personal", ""),
        }

    def _get_config(self, variables):
        return {
            "base_url": self._get_value(
                "PASSBOLT_BASE_URL", variables, variables.get("environment")
            ),
            "private_key": self._get_value(
                "PASSBOLT_PRIVATE_KEY", variables, variables.get("environment")
            ),
            "passphrase": self._get_value(
                "PASSBOLT_PASSPHRASE", variables, variables.get("environment")
            ),
            "gpg_binary": self._get_value(
                "PASSBOLT_GPG_BINARY", variables, variables.get("environment"), default="gpg"
            ),
            "gpg_library": self._get_value(
                "PASSBOLT_GPG_LIBRARY", variables, variables.get("environment"), default="PGPy"
            ),
            "fingerprint": self._get_value(
                "PASSBOLT_FINGERPRINT", variables, variables.get("environment")
            ),
            "verify": self._get_value(
                "PASSBOLT_VERIFY", variables, variables.get("environment"), default=True
            ),
            "create_new_resource": self._get_value(
                "PASSBOLT_CREATE_NEW_RESOURCE", variables,
                variables.get("environment"),
                default=False,
            ),
            "new_resource_password_length": self._get_value(
                "PASSBOLT_NEW_RESOURCE_PASSWORD_LENGTH", variables,
                variables.get("environment"),
                default=20,
            ),
            "new_resource_password_special_chars": self._get_value(
                "PASSBOLT_NEW_RESOURCE_PASSWORD_SPECIAL_CHARS", variables,
                variables.get("environment"),
                default=False,
            ),
        }

    def passbolt_init(self, variables, kwargs):
        self.dict_config = self._get_config(variables)
        self.p = PassboltAPI(dict_config=self.dict_config)
        self.passbolt_resources = self.p.get_resources()

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        self.passbolt_init(variables, kwargs)
        return self.passbolt_resources