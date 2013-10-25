# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Amazon EC2, Eucalyptus and Nimbus drivers.
"""

from __future__ import with_statement

import sys
import base64
import os
import copy

from xml.etree import ElementTree as ET

from libcloud.utils.py3 import b, basestring

from libcloud.utils.xml import fixxpath, findtext, findattr, findall
from libcloud.utils.publickey import get_pubkey_ssh2_fingerprint
from libcloud.utils.publickey import get_pubkey_comment
from libcloud.utils.iso8601 import parse_date
from libcloud.common.aws import AWSBaseResponse, SignedAWSConnection
from libcloud.common.types import (InvalidCredsError, MalformedResponseError,
                                   LibcloudError)
from libcloud.compute.providers import Provider
from libcloud.compute.types import NodeState
from libcloud.compute.base import Node, NodeDriver, NodeLocation, NodeSize
from libcloud.compute.base import NodeImage, StorageVolume, VolumeSnapshot
from libcloud.compute.drivers.ec2 import *


API_VERSION = '2010-08-31'
NAMESPACE = 'http://ec2.amazonaws.com/doc/%s/' % (API_VERSION)


class BaseEC2SpotNodeDriver(BaseEC2NodeDriver):
    
    connectionCls = EC2Connection
    features = {'create_node': ['ssh_key']}
    path = '/'

    NODE_STATE_MAP = {
        'pending': NodeState.PENDING,
        'running': NodeState.RUNNING,
        'shutting-down': NodeState.UNKNOWN,
        'terminated': NodeState.TERMINATED
    }


    def create_node(self, **kwargs):
        """Create a new EC2 Spot Instance

        Reference: http://bit.ly/8ZyPSy [docs.amazonwebservices.com]

        @inherits: :class:`NodeDriver.create_node`

        :keyword    bid: Maximum price of the instance for the bid
        :type       bid: ``int``

        :keyword    ex_maxcount: Maximum number of instances to launch
        :type       ex_maxcount: ``int``

        :keyword    ex_security_groups: A list of names of security groups to
                                        assign to the node.
        :type       ex_security_groups:   ``list``

        :keyword    ex_keyname: The name of the key pair
        :type       ex_keyname: ``str``

        :keyword    ex_userdata: User data
        :type       ex_userdata: ``str``

        :keyword    ex_clienttoken: Unique identifier to ensure idempotency
        :type       ex_clienttoken: ``str``

        :keyword    ex_blockdevicemappings: ``list`` of ``dict`` block device
                    mappings. Example:
                    [{'DeviceName': '/dev/sda1', 'Ebs.VolumeSize': 10},
                     {'DeviceName': '/dev/sdb', 'VirtualName': 'ephemeral0'}]
        :type       ex_blockdevicemappings: ``list`` of ``dict``

        :keyword    ex_iamprofile: Name or ARN of IAM profile
        :type       ex_iamprofile: ``str``
        """
        image = kwargs["image"]
        size = kwargs["size"]
        params = {
            'Action': 'RequestSpotInstances',
            'SpotPrice': kwargs.get('bid', 0.25),
            'LaunchSpecification.ImageId': image.id,
            'InstanceCount': str(kwargs.get('ex_maxcount', '1')),
            'LaunchSpecification.InstanceType': size.id
        }

        if 'ex_security_groups' in kwargs and 'ex_securitygroup' in kwargs:
            raise ValueError('You can only supply ex_security_groups or'
                             ' ex_securitygroup')

        # ex_securitygroup is here for backward compatibility
        ex_security_groups = kwargs.get('ex_security_groups', None)
        ex_securitygroup = kwargs.get('ex_securitygroup', None)
        security_groups = ex_security_groups or ex_securitygroup

        if security_groups:
            if not isinstance(security_groups, (tuple, list)):
                security_groups = [security_groups]

            for sig in range(len(security_groups)):
                params['LaunchSpecification.SecurityGroup.%d' % (sig + 1,)] =\
                    security_groups[sig]

        if 'location' in kwargs:
            availability_zone = getattr(kwargs['location'],
                                        'availability_zone', None)
            if availability_zone:
                if availability_zone.region_name != self.region_name:
                    raise AttributeError('Invalid availability zone: %s'
                                         % (availability_zone.name))
                params['AvailabilityZoneGroup'] = availability_zone.name

        if 'auth' in kwargs and 'ex_keyname' in kwargs:
            raise AttributeError('Cannot specify auth and ex_keyname together')

        if 'auth' in kwargs:
            auth = self._get_and_check_auth(kwargs['auth'])
            params['KeyName'] = \
                self.ex_find_or_import_keypair_by_key_material(auth.pubkey)

        if 'ex_keyname' in kwargs:
            params['LaunchSpecification.KeyName'] = kwargs['ex_keyname']

        if 'ex_userdata' in kwargs:
            params['LaunchSpecification.UserData'] = base64.b64encode(b(kwargs['ex_userdata']))\
                .decode('utf-8')

        if 'ex_clienttoken' in kwargs:
            params['ClientToken'] = kwargs['ex_clienttoken']

        if 'ex_blockdevicemappings' in kwargs:
            if not isinstance(kwargs['ex_blockdevicemappings'], (list, tuple)):
                raise AttributeError(
                    'ex_blockdevicemappings not list or tuple')

            for idx, mapping in enumerate(kwargs['ex_blockdevicemappings']):
                idx += 1  # we want 1-based indexes
                if not isinstance(mapping, dict):
                    raise AttributeError(
                        'mapping %s in ex_blockdevicemappings '
                        'not a dict' % mapping)
                for k, v in mapping.items():
                    params['LaunchSpecification.BlockDeviceMapping.%d.%s' % (idx, k)] = str(v)

        if 'ex_iamprofile' in kwargs:
            if not isinstance(kwargs['ex_iamprofile'], basestring):
                raise AttributeError('ex_iamprofile not string')

            if kwargs['ex_iamprofile'].startswith('arn:aws:iam:'):
                params['LaunchSpecification.IamInstanceProfile.Arn'] = kwargs['ex_iamprofile']
            else:
                params['LaunchSpecification.IamInstanceProfile.Name'] = kwargs['ex_iamprofile']

        object = self.connection.request(self.path, params=params).object
        nodes = self._to_nodes(object, 'instancesSet/item')

        for node in nodes:
            tags = {'Name': kwargs['name']}

            try:
                self.ex_create_tags(resource=node, tags=tags)
            except Exception:
                continue

            node.name = kwargs['name']
            node.extra.update({'tags': tags})

        if len(nodes) == 1:
            return nodes[0]
        else:
            return nodes


class EC2SpotNodeDriver(BaseEC2SpotNodeDriver):
    """
    Amazon EC2 node driver.
    """

    connectionCls = EC2Connection
    type = Provider.EC2
    name = 'Amazon EC2'
    website = 'http://aws.amazon.com/ec2/'
    path = '/'

    NODE_STATE_MAP = {
        'pending': NodeState.PENDING,
        'running': NodeState.RUNNING,
        'shutting-down': NodeState.UNKNOWN,
        'terminated': NodeState.TERMINATED,
        'stopped': NodeState.STOPPED
    }

    def __init__(self, key, secret=None, secure=True, host=None, port=None,
                 region='us-east-1', **kwargs):
        if hasattr(self, '_region'):
            region = self._region

        if region not in VALID_EC2_REGIONS:
            raise ValueError('Invalid region: %s' % (region))

        details = REGION_DETAILS[region]
        self.region_name = region
        self.api_name = details['api_name']
        self.country = details['country']

        self.connectionCls.host = details['endpoint']

        super(EC2SpotNodeDriver, self).__init__(key=key, secret=secret,
                                            secure=secure, host=host,
                                            port=port, **kwargs)

