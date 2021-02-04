from __future__ import absolute_import
import os
import logging

# Path to opendxl config file
CONFIG = "/home/username/opendxl/opendxl-client/dxlclient.config"

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

