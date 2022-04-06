from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    name: passbolt
    author: Jean-Christophe Vassort <jean-christophe@passbolt.com>
    version_added: "0.1"
    short_description: retrieve resources and secrets from passbolt API
    description:
        - This lookup returns resources and secrets from passbolt API.
    options:
      per_uuid:
        description: The searched term is a passbolt resource UUID
        type: bool
        required: False
        default: False
      username:
        description: filter the searched term per username
        type: str
        require: False
        default: ""
      uri:
        description: filter the searched term per uri
        type: str
        require: False
        default: ""
      description:
        description: filter the searched term per description
        type: str
        require: False
        default: ""
"""

EXAMPLES = """
- name: "Passbolt lookup plugin / fetch one"
  debug:
    var: lookup('passbolt', 'OVH')
- name: "Passbolt lookup plugin / loop with filters"
  debug:
    var: item
  loop:
    - "{{ lookup('passbolt', 'Odoo') }}"
    - "{{ lookup('passbolt', 'a294b8d6-5dae-4db6-9e49-f790781cec30', per_uuid='true') }}"
    - "{{ lookup('passbolt', 'OVH', username='zero-cool@ellingson.corp') }}"
    - "{{ lookup('passbolt', 'OVH', username='John Dog') }}"
- name: "Passbolt lookup plugin / fetch list of items"
  debug:
    var: item
  with_passbolt:
    - "n8n"
    - "Scaleway"
    - "This doesn't exists"
- name: Generate AWS credentials profile
  ansible.builtin.copy:
    vars:
      aws:
        access_key: "{{ lookup('passbolt', 'AWS').password }}"
        secret_key: "{{ lookup('passbolt', 'AWS').description }}"
    dest: ${HOME}/.aws/credentials
    owner: "{{ lookup('env', 'USER') }}"
    mode: "0600"
    content: |
      [default]
      aws_access_key_id={{ aws.access_key }}
      aws_secret_access_key={{ aws.secret_key }}
"""

RETURN = """
  _raw:
    description:
      - content of file(s)
    type: list
    elements: str
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text
from ansible.utils.display import Display
from passbolt import PassboltAPI
from os import environ
import json

display = Display()


class LookupModule(LookupBase):
    def _get_env_value(self, selected_variable, environment_variables, default=str()):
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

    def _search(self, item, kwargs):
        res = 0
        expected = len(kwargs)

        for k in kwargs:
            if kwargs[k] == item[k]:
                res += 1

        return expected == res

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
        if variables.get("environment") is None:
            return {
                "base_url": environ.get("PASSBOLT_BASE_URL"),
                "private_key": environ.get("PASSBOLT_PRIVATE_KEY"),
                "passphrase": environ.get("PASSBOLT_PASSPHRASE"),
                "gpg_binary": environ.get("PASSBOLT_GPG_BINARY", "gpg"),
                "gpg_library": environ.get("PASSBOLT_GPG_LIBRARY", "PGPy"),
                "fingerprint": environ.get("PASSBOLT_FINGERPRINT"),
            }
        else:
            return {
                "base_url": self._get_env_value(
                    "PASSBOLT_BASE_URL", variables.get("environment")
                ),
                "private_key": self._get_env_value(
                    "PASSBOLT_PRIVATE_KEY", variables.get("environment")
                ),
                "passphrase": self._get_env_value(
                    "PASSBOLT_PASSPHRASE", variables.get("environment")
                ),
                "gpg_binary": self._get_env_value(
                    "PASSBOLT_GPG_BINARY", variables.get("environment"), default="gpg"
                ),
                "gpg_library": self._get_env_value(
                    "PASSBOLT_GPG_LIBRARY", variables.get("environment"), default="PGPy"
                ),
                "fingerprint": self._get_env_value(
                    "PASSBOLT_FINGERPRINT", variables.get("environment")
                ),
            }

    def run(self, terms, variables=None, **kwargs):

        ret = []

        self.set_options(var_options=variables, direct=kwargs)

        # with open("debug", "w") as f:
        #    f.write(repr(kwargs))
        #    f.write("\n")
        #    f.write(
        #        self._templar.template(
        #            next(
        #                item.get("PASSBOLT_PASSPHRASE")
        #                for item in variables.get("environment")
        #                if item.get("PASSBOLT_PASSPHRASE")
        #            )
        #        )
        #    )
        #    f.write("\n")

        dict_config = self._get_config(variables)

        p = PassboltAPI(dict_config=dict_config)
        if kwargs.get("per_uuid") != "true":
            passbolt_resources = p.get_resources()

        for term in terms:
            display.debug("Passbolt lookup term: %s" % term)

            try:
                if kwargs.get("per_uuid") == "true":
                    resource = p.get_resource_per_uuid(term)
                elif kwargs.get("wantlist"):  # with_passbolt case
                    resource = next(
                        item
                        for item in passbolt_resources
                        if item.get("name", "") == term
                    )
                elif len(kwargs):
                    kwargs["name"] = term
                    resource = next(
                        (
                            item
                            for item in passbolt_resources
                            if self._search(item, kwargs)
                        ),
                        str(),
                    )
                else:
                    resource = next(
                        (item for item in passbolt_resources if item["name"] == term),
                        str(),
                    )
                resource_secrets = (
                    dict_config.get("gpg_library", "PGPy") == "gnupg"
                    and json.loads(
                        p.decrypt(p.get_resource_secret(resource["id"])).data
                    )
                    or json.loads(p.decrypt(p.get_resource_secret(resource["id"])))
                )

                ret.append(self._format_result(resource, resource_secrets))

            except:
                ret.append(self._format_result(dict(), dict()))

        return ret


# from passbolt import PassboltAPI
# import json
#
# p = PassboltAPI('AC0E164DDAF64C04282FA0A8AD36A0D907DB21C9')
# p.get_resources()
# resource_id = next(item for item in p.get_resources() if item["name"] == "docker.com token for gitlab")['id']
# res = json.loads(p.decrypt(p.get_resource_secret(resource_id)).data)
#
## print password
# print (res['password'])
