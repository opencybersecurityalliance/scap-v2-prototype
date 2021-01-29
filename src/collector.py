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
import hashlib
import datetime

from dxlclient.callbacks import RequestCallback, ResponseCallback, EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request, Response
from dxlclient.message import Event
from dxlclient.service import ServiceRegistrationInfo
from messages import ReportResultsMessage, MessageType, QueryMessage, QueryResultMessage, RegistrationMessage, CollectorRequestMessage

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Parse the Collector configuration file 
if len(sys.argv) == 1:
    print("Please specify a config file.")
    sys.exit()

collector_config = open(sys.argv[1])
j = json.load(collector_config)
COLLECTOR_ID = j["collector_id"]
make = j["make"]
model = j["model"]

# Topic that the collector listens on for collection request events
EVENT_COLLECTOR_REQUEST_TOPIC = "/scap/event/collector/request" + "/" + COLLECTOR_ID

# Topic to send collector requests to the PCX
EVENT_PCX_COLLECTOR_REQUEST_TOPIC = "/scap/event/pcx/collector/request"

# Topic to send collection requests to PCEs
SERVICE_PCE_REQUEST_TOPIC = "/scap/service/pce/request"

# Topic to send query requests to the repository
SERVICE_REPOSITORY_QUERY_TOPIC = "/scap/service/repository/query"

# Base topic that the collector uses to send assessment results to an application
EVENT_ASSESSMENT_RESULTS_TOPIC = "/scap/event/assessment/results"

# Topic that the collector listens on for PCE registration requests
EVENT_PCE_REGISTRATION_TOPIC = "/scap/event/pce/registration/" + COLLECTOR_ID

# Topic that repository listens for data to store
EVENT_STORE_DATA_TOPIC = "/scap/event/data/store"

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Stores all incoming collection requests that                                                                      
# need to be processed
collection_requests = []

# Stores all the PCEs registered to the Collector
pces = {}

# Stores all the PCXs registered to the Collector  
pcx_pces = {}

# Create the client
with DxlClient(config) as client:

    # Get all PCXs associated with the target
    def get_pcxs(targets):
        p = []
        for target in targets:
            if target in pcx_pces.keys():
                for pcx in pcx_pces[target]:
                    if pcx not in p:
                        p.append(pcx)
        return p

    # Get all PCEs associated with the target
    def get_pces(targets):
        p = []
        for target in targets:
            if target in pces.keys():
                for pce in pces[target]:
                    if pce not in p:
                        p.append(pce)
        return p

    # Convert content into a format understandable by the PCE                                                     
    def convert_content(content):
        return content

    # Task the PCE with an collection request
    def task_pce(crm, pce_id):
        logger.info("Tasking PCE: %s", crm.to_s())

        # Get content and perform any content conversions
        # before sending to PCE. If cancellation message
        # just send that to the PCE.
        if crm.ids == "":
            content = "cancel_" + str(crm.transaction_id)
        else:
            content = get_content(crm.ids)
            content = convert_content(content)

        # Send the collection request to the identified PCE
        request = Request(SERVICE_PCE_REQUEST_TOPIC + "/" + pce_id)
        request.payload = content.encode()
        response = client.sync_request(request)

        if response.message_type != Message.MESSAGE_TYPE_ERROR:
            # Only send results if not a cancel message
            if crm.ids != "":
                rrsm = ReportResultsMessage()
                rrsm.assessment_results = response.payload.decode()
                rrsm.transaction_id = crm.transaction_id
                rrsm.requestor_id = crm.requestor_id
                rrsm.target_id = lookup_target_id(pce_id)
                rrsm.collector_id = COLLECTOR_ID
                rrsm.pce_id = pce_id
                rrsm.timestamp = str(datetime.datetime.now())

                # Apply collection parameters                                                                       
                cp_rrsm = apply_collection_parameters(rrsm, crm.collection_parameters)
                store_data(cp_rrsm)

                # Apply result format and filters and send to the
                # appropriate application                                                                      
                rff_rrsm = apply_format_and_filters(rrsm, crm.result_format_filters)
                send_collection_results_event(rff_rrsm)

        return

    # Get the target id associated with the specified
    # PCE id 
    def lookup_target_id(pce_id):
        for k in pces.keys():
            if pce_id in pces[k]:
                return k

    # Task the PCX with a collection request
    def task_pcx(crm, pcx_id):
        logger.info("Tasking PCX: %s", crm.to_s())
        send_event(EVENT_PCX_COLLECTOR_REQUEST_TOPIC + "/" + pcx_id, crm.to_json())

    # Check local cache for PCE instructions
    def check_local_cache(ids):
        if ids == "1,2,3":
            return "inventory"
        elif ids == "4,5,6":
            return "assess"
        elif ids == "7,8,9":
            return "remaining_request"
        elif ids == "":
            return ""
        else:
            return "some cached content"

    # Get content either from local cache or repository
    def get_content(ids):
        # Check local cache
        content = check_local_cache(ids)

        # If missing get from repository
        if content == "":
            qrm = query_repository("content_ids")
            content = qrm.result
        return content

    # Compute the target identifier based on the collected
    # asset information                                                                              
    def get_target_id(asset_info):
        info = bytes(asset_info)
        hash_object = hashlib.md5(info)
        return hash_object.hexdigest()

    # Get all the PCE ids stored in the
    # collection methods property 
    def get_pce_ids(collection_methods):
        cms = json.loads(collection_methods)
        pce_ids = []
        for cm in cms:
            print(cm)
            pce_ids.append(cm["pce-id"])
        return pce_ids

    # Query the repository for certain information
    def query_repository(query):
        # Create query message and send it to the repository
        req = Request(SERVICE_REPOSITORY_QUERY_TOPIC)
        qm = QueryMessage(query)
        req.payload = (qm.to_json()).encode()
        res = client.sync_request(req)

        # Parse and return the query results
        qrm = QueryResultMessage()
        qrm.parse(res.payload.decode())
        return qrm

    # Send assessment results event to the appropriate application
    def send_collection_results_event(rrsm):
        logger.info("Sending report results to application %s : %s", rrsm.requestor_id, rrsm.to_s())
        send_event(EVENT_ASSESSMENT_RESULTS_TOPIC + "/" + rrsm.requestor_id, rrsm.to_json())

    # Store data in the repository                                                                             
    def store_data(m):
        logger.info("Storing data in the repository: %s", m.to_s())
        send_event(EVENT_STORE_DATA_TOPIC, m.to_json())

    # Send event to the specified topic                                                                            
    def send_event(topic, m):
        event = Event(topic)
        event.payload = m.encode()
        client.send_event(event)

    # Apply collection parameters to report results
    def apply_collection_parameters(rrsm, collection_parameters):
        return rrsm

    # Apply format and filters to report results
    def apply_format_and_filters(rrsm, result_format_filters):
        return rrsm

    # Process incoming collection events
    class CollectionEventCallback(EventCallback):
        def on_event(self, event):
            crm = CollectorRequestMessage()
            crm.parse(event.payload.decode())
            collection_requests.append(crm)

    # Process incoming registration events
    class RegistrationEventCallback(EventCallback):
        def on_event(self, event):

            # Parse the registration message and add PCE
            # to the list of known PCEs
            rm = RegistrationMessage()
            rm.parse(event.payload.decode())

            # Check if it is coming from a PCX
            if rm.pcx_id != "":
                if rm.target_id in pcx_pces.keys():
                    if rm.pcx_id not in pcx_pces[rm.target_id]:
                        pcx_pces[rm.target_id].append(rm.pcx_id)
                else:
                    # Add PCX to the list of registered PCXs
                    # and set the collector properties of the
                    # registration message
                    pcx_pces[rm.target_id] = [rm.pcx_id]
                    rm.collector_id = COLLECTOR_ID
                    rm.collector_make = make
                    rm.collector_model = model

                    # Only store in the repository if this target
                    # wasn't already identified by PCE
                    if rm.target_id not in pces.keys():
                        store_data(rm)
            # Coming from a PCE
            else:
                # Generate a target id for the endpoint
                # based on asset information
                target_id = get_target_id(rm.asset_info)

                # If the target is already known just add
                # the PCE to the list of registered PCEs
                if target_id in pces.keys():
                    pces[target_id].append(rm.pce_id)
                # Otherwise, the target is not known so
                # add the target id along with the PCE
                # to the list of registered PCEs and fill
                # out the collector properties of the 
                # registration message
                else:
                    pces[target_id] = [rm.pce_id]
                    rm.collector_id = COLLECTOR_ID
                    rm.target_id = target_id
                    rm.collector_make = make
                    rm.collector_model = model

                    # Only store in the repository if this target
                    # wasn't already identified by a PCX
                    if rm.target_id not in pcx_pces.keys():
                        store_data(rm)

    # Prepare service registration information
    info = ServiceRegistrationInfo(client, "/scap/collector")

    # Connect to the message fabric and add a listener for registration events
    # and collection requests
    client.connect()
    client.add_event_callback(EVENT_COLLECTOR_REQUEST_TOPIC, CollectionEventCallback())
    client.add_event_callback(EVENT_PCE_REGISTRATION_TOPIC, RegistrationEventCallback())
    client.register_service_sync(info, 10)

    # Wait forever
    while True:
        # Process all collection requests that were received
        while collection_requests:
            crm = collection_requests.pop(0)

            # Get all PCXs and PCEs based on
            # the specified targets
            pcx_ids = get_pcxs(crm.targets)
            pce_ids = get_pces(crm.targets)

            # Task all PCXs with collection
            for pcx_id in pcx_ids:
                task_pcx(crm, pcx_id)

            # Task all PCEs with collection
            for pce_id in pce_ids:
                task_pce(crm, pce_id)

        time.sleep(1)
