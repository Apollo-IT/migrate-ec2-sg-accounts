#!/usr/bin/python
# -*- coding: utf8 -*-

import argparse
import logging
import os
import sys

import boto.ec2
import boto.exception

logging.basicConfig(format='%(asctime)s %(pathname)s:%(lineno)s [%(levelname)s] %(message)s',
                    level=logging.INFO)


def migrate_groups(origin, dest, groups, from_aws_key, from_aws_secret, to_aws_key, to_aws_secret):
    from_conn = boto.ec2.connect_to_region(origin, aws_access_key_id=from_aws_key,
                                           aws_secret_access_key=from_aws_secret)
    to_conn = boto.ec2.connect_to_region(dest, aws_access_key_id=to_aws_key,
                                         aws_secret_access_key=to_aws_secret)

    # test connections
    try:
        from_conn.describe_account_attributes()
        to_conn.describe_account_attributes()
    except Exception as e:
        logging.error(
            'please make sure that you set your EC2 credentials and that they are correct')
        sys.exit(0)

    from_groups = from_conn.get_all_security_groups()
    logging.debug("from groups: %s" % from_groups)
    to_groups = [group.name for group in to_conn.get_all_security_groups()]
    logging.debug("to groups: %s" % to_groups)
    for from_group in from_groups:
        if from_group.name not in groups:
            continue

        if from_group.name in to_groups:
            logging.warn("security group with name '%s' already exists on region '%s'" % (
                from_group.name, dest))
            continue

        try:
            logging.info("migrating group %s from %s to %s" % (from_group.name, origin, dest))
            new_group = to_conn.create_security_group(from_group.name, from_group.name)
            for rule in from_group.rules:
                if not rule.grants[0].cidr_ip:
                    new_group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip="0.0.0.0/0")
                else:
                    new_group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.grants[0].cidr_ip)
        except Exception as e:
            logging.error("error migrating group %s from %s to %s: %s" % (
                from_group.name, origin, dest, e))
            continue
        logging.info(
            "migrated group '%s' from '%s' to '%s' successfully!" % (from_group.name, origin, dest))


if __name__ == '__main__':

    FROM_AWS_KEY = ''
    FROM_AWS_SECRET = ''

    TO_AWS_KEY = ''
    TO_AWS_SECRET = ''

    parser = argparse.ArgumentParser(
        description='example: migrate.py us-west-2 eu-west-1 default prod-security ...')
    parser.add_argument('origin', help='EC2 region to export FROM')
    parser.add_argument('dest', help='EC2 region to import TO')
    parser.add_argument('groups', nargs='+', help='EC2 security groups\' names')
    parser.add_argument('--from_key', nargs='?', help='FROM_AWS_KEY')
    parser.add_argument('--from_secret', nargs='?', help='FROM_AWS_SECRET')
    parser.add_argument('--to_key', nargs='?', help='TO_AWS_KEY')
    parser.add_argument('--to_secret', nargs='?', help='TO_AWS_SECRET')
    args = parser.parse_args()

    from_region = args.origin
    to_region = args.dest
    groups = args.groups

    # 1st check - command line arguments
    if args.from_key and args.from_secret:
        FROM_AWS_KEY = args.from_key
        FROM_AWS_SECRET = args.from_secret

    if args.to_key and args.to_secret:
        TO_AWS_KEY = args.to_key
        TO_AWS_SECRET = args.to_secret

    # 2nd check - aws_credentials.cfg
    if not FROM_AWS_KEY or not FROM_AWS_SECRET:
        props_dict = {}
        for line in open('aws_credentials.cfg', 'r').readlines():
            line = line.strip()
            prop, value = line.split('=')
            props_dict[prop] = value

        if 'FROM_AWS_KEY' in props_dict and 'FROM_AWS_SECRET' in props_dict:
            FROM_AWS_KEY = props_dict['FROM_AWS_KEY']
            FROM_AWS_SECRET = props_dict['FROM_AWS_SECRET']

        if 'TO_AWS_KEY' in props_dict and 'TO_AWS_SECRET' in props_dict:
            TO_AWS_KEY = props_dict['TO_AWS_KEY']
            TO_AWS_SECRET = props_dict['TO_AWS_SECRET']

    # 3rd check - environment variables
    if not FROM_AWS_KEY or not FROM_AWS_SECRET:
        if 'AWS_KEY' in os.environ and 'AWS_SECRET' in os.environ:
            FROM_AWS_KEY = os.environ['AWS_KEY']
            FROM_AWS_SECRET = os.environ['AWS_SECRET']

    # 3rd check - environment variables
    if not TO_AWS_KEY or not TO_AWS_SECRET:
        if 'AWS_KEY' in os.environ and 'AWS_SECRET' in os.environ:
            TO_AWS_KEY = os.environ['AWS_KEY']
            TO_AWS_SECRET = os.environ['AWS_SECRET']

    migrate_groups(origin=from_region, dest=to_region, groups=groups, from_aws_key=FROM_AWS_KEY, from_aws_secret=FROM_AWS_SECRET, to_aws_key=TO_AWS_KEY, to_aws_secret=TO_AWS_SECRET)
