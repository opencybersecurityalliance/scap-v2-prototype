# NOTICE                                                                                                                
#                                                                                                                       
# This software was produced for the U. S. Government under Basic Contract No.                                          
# W56KGU-19-D-0004, and is subject to the Rights in Noncommercial Computer                                              
# Software and Noncommercial Computer Software Documentation Clause                                                     
# 252.227-7014 (FEB 2012)                                                                                               
#
# (c) 2020 The MITRE Corporation. Approved for Public Release. Distribution Unlimited. Case Number 20-2258

import logging
import os
import sys
import time
import json
import re

from dxlclient.callbacks import RequestCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Request, Response, Event
from dxlclient.service import ServiceRegistrationInfo
from messages import InitiateAssessmentMessage, ReportResultsMessage, RegistrationMessage, CollectorRequestMessage

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Parse the PCE configuration file
if len(sys.argv) == 1:
    print("Please specify a config file.")
    sys.exit()

pce_config = open(sys.argv[1])
j = json.load(pce_config)
OS = j["os"]
PCE_ID = j["pce_id"]
MAKE = j["make"]
MODEL = j["model"]
ASSET = j["asset"]
SOFTWARE = json.dumps(j["software"])
SUPPORTED_CHECK_TYPES = json.dumps(j["supported_check_types"])
REGISTER_TO = j["register_to"]

# Topic that the PCE listens on for collection requests
SERVICE_PCE_REQUEST_TOPIC = "/scap/service/pce/request/"+PCE_ID

# Topic that the PCX/collector listens on for PCE registration requests
EVENT_PCE_REGISTRATION_TOPIC = "/scap/event/pce/registration/" + REGISTER_TO

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG)

# Stores the collection requests for processing
collection_requests = []

# Create the client
with DxlClient(config) as client:

    # Perfom the collection on the endpoint and return the results
    def perform_collection(instructions):
        if instructions == "inventory":
            assessment_results = SOFTWARE
        elif instructions == "assess":
            assessment_results = "pce "+OS+" assessment results ("+PCE_ID+")"
        elif instructions == "remaining_request":
            assessment_results = "remaining "+OS+" results ("+PCE_ID+")"
        else:
            assessment_results = "unknown results"

        return assessment_results

    # Process incoming collection requests from the manager                                                         
    class PCERequestCallback(RequestCallback):
        def on_request(self, request):            
            logger.info("PCE received payload: %s", request.payload.decode())
            collection_requests.append(request)

    # Prepare service registration information                                                                 
    info = ServiceRegistrationInfo(client, "/scap/pce"+PCE_ID)
    info.add_topic(SERVICE_PCE_REQUEST_TOPIC, PCERequestCallback())

    # Connect to the message fabric and add a listener for registration events
    client.connect()
    client.register_service_sync(info, 10)

    # Register PCE by sending registration event to the collector/PCX
    event = Event(EVENT_PCE_REGISTRATION_TOPIC)
    rm = RegistrationMessage(PCE_ID, "", "", ASSET, MAKE, MODEL, "", "", "", "", "", SUPPORTED_CHECK_TYPES)
    event.payload = (rm.to_json()).encode()
    logger.info("Sending registration event: %s", rm.to_s())
    client.send_event(event)
    
    # Wait forever
    while True:
        # Process all collection requests that were received
        while collection_requests:
            request = collection_requests.pop()
            response = Response(request)

            # Cancel assessment if a cancel request. Otherwise,
            # perform the assessment
            if re.search("cancel_.*",request.payload.decode()):
                transaction_id = request.payload.decode().split("_")[1]
                logger.info("Canceling assessment "+transaction_id)
                response.payload = "".encode()
            else:
                response.payload = perform_collection(request.payload.decode()).encode()

            # Send results back to the collector/PCX
            logger.info("Service sending: %s", response.payload.decode())
            client.send_response(response)
            
        time.sleep(1)
