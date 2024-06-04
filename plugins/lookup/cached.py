"""
Source: https://github.com/GoodRx/ansible-cached-lookup/pull/5

An Ansible lookup plugin that caches the results of any other lookup, most
useful in group/host vars.
By default, Ansible evaluates any lookups in a group/host var whenever the var
is accessed. For example, given a group/host var:
.. code-block:: yaml
    content: "{{ lookup('pipe', 'a-very-slow-command') }}"
any tasks that access ``content`` (e.g. in a template) will re-evaluate
the lookup, which adds up very quickly.
.. seealso:: :attr:`.DOCUMENTATION`, :attr:`.EXAMPLES`, `ansible/ansible#9623
    <https://github.com/ansible/ansible/issues/9623>`_
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os.path

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader
from ansible.plugins.lookup import LookupBase

__version__ = "1.0.1"


DOCUMENTATION = """
lookup: cached
short_description: cache the result of a lookup in memory
description:
  - Run a lookup and cache the result for the duration of the play. This is
    most useful for lookups in group/host vars, which are typically
    re-evaluated every time they are used
options:
  _terms:
    description: the lookup and any arguments
    required: True
notes:
  - This code has been updated to do in-memory cache
"""

EXAMPLES = """
group_var1: "{{ lookup('cached', 'pipe', 'a-very-slow-command') }}"
"""


cache = dict()
try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display

    display = Display()

class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        lookup_name, terms = terms[0], terms[1:]
        global cache
        key = terms[0]

        try:
            result = cache[key]
            display.verbose("'cached' lookup cache hit for %r" % (key,))
        except KeyError:
            # Based on
            # https://github.com/ansible/ansible/blob/v2.6.1/lib/ansible/vars/manager.py#L495
            lookup = lookup_loader.get(
                lookup_name, loader=self._loader, templar=self._templar
            )
            if lookup is None:
                raise AnsibleError("lookup plugin (%s) not found" % lookup_name)

            result = lookup.run(terms, variables=variables, **kwargs)
            cache[key] = result
            display.verbose("'cached' lookup cache miss for %r" % (key,))

        return result