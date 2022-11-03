#!/usr/bin/env python3
import re

DOCUMENTATION = """
    name: passbolt_nameing_check
    author: Florian Schwehla <github@fschwehla.de>
    version_added: "0.1"
    description: Uses the output of the passbolt inventory lookup and a regex string to check if the passwords match the naming guideline
"""


def all_secrets(d: dict, regexfil: str):
    if type(d) == list:
        uncompliant_secrets = []
        for sec in d:
            uncompliant_secret = {}
            for i in sec.items():
                if i[0] == "name":
                    if not re.match(regexfil, i[1]):
                        uncompliant_secret.update({'name': sec['name']})
                        uncompliant_secret.update({'user': sec['username']})
                        uncompliant_secrets.append(uncompliant_secret)
        return uncompliant_secrets
    else:
        for i in d.items():
            if i[0] == "name":
                if not re.match(regexfil, i[1]):
                    raise Exception((i[1]+" is not compliant"))
                else:
                    return (i[1]+" is compliant")


class FilterModule(object):
    def filters(self) -> dict:
        return {"check_naming": self.check_naming}

    def check_naming(self, s, regexfil) -> dict:
        return all_secrets(s, regexfil)
