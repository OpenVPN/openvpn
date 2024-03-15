#!/usr/bin/env python3

#  Copyright (C) 2023-2024 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2023-2024 Frank Lichtenheld <frank.lichtenheld@openvpn.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Extract a patch from Gerrit and transform it in a file suitable as input
# for git send-email.

import argparse
import base64
from datetime import timezone
import json
import sys
from urllib.parse import urlparse

import dateutil.parser
import requests


def get_details(args):
    params = {"o": ["CURRENT_REVISION", "LABELS", "DETAILED_ACCOUNTS"]}
    r = requests.get(f"{args.url}/changes/{args.changeid}", params=params)
    print(r.url)
    json_txt = r.text.removeprefix(")]}'\n")
    json_data = json.loads(json_txt)
    assert len(json_data["revisions"]) == 1  # CURRENT_REVISION works as expected
    revision = json_data["revisions"].popitem()[1]["_number"]
    assert "Code-Review" in json_data["labels"]
    acked_by = []
    for reviewer in json_data["labels"]["Code-Review"]["all"]:
        if "value" in reviewer:
            assert reviewer["value"] >= 0  # no NACK
            if reviewer["value"] == 2:
                # fall back to user name if optional fields are not set
                reviewer_name = reviewer.get("display_name", reviewer["name"])
                reviewer_mail = reviewer.get("email", reviewer["name"])
                ack = f"{reviewer_name} <{reviewer_mail}>"
                print(f"Acked-by: {ack}")
                acked_by.append(ack)
    # construct Signed-off-by in case it is missing
    owner = json_data["owner"]
    owner_name = owner.get("display_name", owner["name"])
    owner_mail = owner.get("email", owner["name"])
    sign_off = f"{owner_name} <{owner_mail}>"
    print(f"Signed-off-by: {sign_off}")
    change_id = json_data["change_id"]
    # assumes that the created date in Gerrit is in UTC
    utc_stamp = (
        dateutil.parser.parse(json_data["created"])
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )
    # convert to milliseconds as used in message id
    created_stamp = int(utc_stamp * 1000)
    hostname = urlparse(args.url).hostname
    msg_id = f"gerrit.{created_stamp}.{change_id}@{hostname}"
    return {
        "revision": revision,
        "project": json_data["project"],
        "target": json_data["branch"],
        "msg_id": msg_id,
        "acked_by": acked_by,
        "sign_off": sign_off,
    }


def get_patch(details, args):
    r = requests.get(
        f"{args.url}/changes/{args.changeid}/revisions/{details['revision']}/patch?download"
    )
    print(r.url)
    patch_text = base64.b64decode(r.text).decode()
    return patch_text


def apply_patch_mods(patch_text, details, args):
    comment_start = patch_text.index("\n---\n") + len("\n---\n")
    signed_off_text = ""
    signed_off_comment = ""
    try:
        signed_off_start = patch_text.rindex("\nSigned-off-by: ")
        signed_off_end = patch_text.index("\n", signed_off_start + 1) + 1
    except ValueError:  # Signed-off missing
        signed_off_text = f"Signed-off-by: {details['sign_off']}\n"
        signed_off_comment = "\nSigned-off-by line for the author was added as per our policy.\n"
        signed_off_end = patch_text.index("\n---\n") + 1
    assert comment_start > signed_off_end
    acked_by_text = ""
    acked_by_names = ""
    for ack in details["acked_by"]:
        acked_by_text += f"Acked-by: {ack}\n"
        acked_by_names += f"{ack}\n"
    patch_text_mod = (
        patch_text[:signed_off_end]
        + signed_off_text
        + acked_by_text
        + patch_text[signed_off_end:comment_start]
        + f"""
This change was reviewed on Gerrit and approved by at least one
developer. I request to merge it to {details["target"]}.

Gerrit URL: {args.url}/c/{details["project"]}/+/{args.changeid}
This mail reflects revision {details["revision"]} of this Change.
{signed_off_comment}
Acked-by according to Gerrit (reflected above):
{acked_by_names}
        """
        + patch_text[comment_start:]
    )
    filename = f"gerrit-{args.changeid}-{details['revision']}.patch"
    patch_text_final = patch_text_mod.replace("Subject: [PATCH]", f"Subject: [PATCH v{details['revision']}]")
    with open(filename, "w", encoding="utf-8", newline="\n") as patch_file:
        patch_file.write(patch_text_final)
    print("send with:")
    print(f"git send-email --in-reply-to {details['msg_id']} {filename}")


def main():
    parser = argparse.ArgumentParser(
        prog="gerrit-send-mail",
        description="Send patchset from Gerrit to mailing list",
    )
    parser.add_argument("changeid")
    parser.add_argument("-u", "--url", default="https://gerrit.openvpn.net")
    args = parser.parse_args()

    details = get_details(args)
    patch = get_patch(details, args)
    apply_patch_mods(patch, details, args)


if __name__ == "__main__":
    sys.exit(main())
