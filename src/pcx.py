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
import hashlib
import datetime

from dxlclient.callbacks import RequestCallback, ResponseCallback, EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request, Response, Event
from dxlclient.service import ServiceRegistrationInfo
from messages import ReportResultsMessage, RegistrationMessage, CollectorRequestMessage

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Parse the PCX configuration file                                                                                  
if len(sys.argv) == 1:
    print("Please specify a config file.")
    sys.exit()

pcx_config = open(sys.argv[1])
j = json.load(pcx_config)

PCX_ID = j["pcx_id"]
MAKE = j["make"]
MODEL = j["model"]
COLLECTOR_ID = j["register_to"]

# Topic that the PCX listens on for collection requests
EVENT_PCX_COLLECTOR_REQUEST_TOPIC = "/scap/event/pcx/collector/request/" + PCX_ID

# Topic to send collection requests to PCEs
SERVICE_PCE_REQUEST_TOPIC = "/scap/service/pce/request"

# Topic that the PCX listens on for PCE registration requests                                                       
EVENT_PCE_REGISTRATION_TOPIC = "/scap/event/pce/registration/" + PCX_ID

# Topic that the collector listens on for PCE registration requests
EVENT_PCE_COLLECTOR_REGISTRATION_TOPIC = "/scap/event/pce/registration/" + COLLECTOR_ID

# Base topic that the PCX uses to send assessment results to an application                                        
EVENT_ASSESSMENT_RESULTS_TOPIC = "/scap/event/assessment/results"

# Topic that repository listens for data to store
EVENT_STORE_DATA_TOPIC = "/scap/event/data/store"

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG)

# Stores all incoming collection requests that
# need to be processed
collection_requests = []

# Stores all the PCEs registered to the PCX
pces = {}

# Create the client
with DxlClient(config) as client:

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
        req = Request(SERVICE_PCE_REQUEST_TOPIC + "/" + pce_id)
        req.payload = content
        res = client.sync_request(req)

        if res.message_type != Message.MESSAGE_TYPE_ERROR:
            # Only send results if not a cancel message
            if crm.ids != "":
                rrsm = ReportResultsMessage()
                rrsm.assessment_results = res.payload.decode()
                rrsm.transaction_id = crm.transaction_id
                rrsm.requestor_id = crm.requestor_id
                rrsm.target_id = lookup_target_id(pce_id)
                rrsm.collector_id = COLLECTOR_ID
                rrsm.pcx_id = PCX_ID
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

    # Get all the PCEs associated with a
    # specific target id. 
    def get_pces(target_id):
        if target_id in pces.keys():
            return pces[target_id]
        else:
            return []

    # Get the target id associated
    # with the specified PCE id.
    def lookup_target_id(pce_id):
        for k in pces.keys():
            if pce_id in pces[k]:
                return k

    # Get content either from local cache or repository
    def get_content(ids):

        # Check local cache                                                                                      
        content = check_local_cache(ids)

        # If missing get from repository
        if content == "":
            qrm = query_repository("content_ids")
            content = qrm.result
        return content

    # Get all the PCE ids stored in the
    # collection methods property
    def get_pce_ids(collection_methods):
        cms = json.loads(collection_methods)
        pce_ids = []
        for cm in cms:
            pce_ids.append(cm["pce-id"])
        return pce_ids

    # Query the repository for certain information                                                                 
    def query_repository(query):
        # Create query message and send it to the repository                                                      
        req = Request(SERVICE_REPOSITORY_QUERY_TOPIC)
        qm = QueryMessage(query)
        req.payload = (qm.to_json()).encode()

        # Parse and return the query results                                                                
        res = client.sync_request(req)
        qrm = QueryResultMessage()
        rm.parse(res.payload.decode())
        return qrm

    # Compute the target identifier based on the collected
    # asset information
    def get_target_id(asset_info):
        info = json.dumps(asset_info).encode("UTF-8")
        hash_object = hashlib.md5(info)
        return hash_object.hexdigest()

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

    # Process incoming collection request events                                                            
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
            m = RegistrationMessage()
            m.parse(event.payload.decode())
            logger.info("Received registration message: %s", m.to_s())

            # Get target id based on endpoint asset information
            target_id = get_target_id(m.asset_info)

            # Check if we already know about target_id
            if target_id in pces.keys():
                # Check if PCE is already associated with target_id
                if m.pce_id not in pces[target_id]:
                    pces[target_id].append(m.pce_id)
            # We don't know about target_id (new endpoint)
            else:
                # Add target_id and PCE to list of PCEs
                pces[target_id] = [m.pce_id]
                m.pcx_id = PCX_ID
                m.target_id = target_id
                m.pcx_make = MAKE
                m.pcx_model = MODEL

                # Forward the registration message to the collector 
                send_event(EVENT_PCE_COLLECTOR_REGISTRATION_TOPIC, m.to_json())

    # Prepare service registration information                                                                      
    info = ServiceRegistrationInfo(client, "/scap/pcx")

    # Connect to the message fabric and add a listener for collection requests and registration events              
    client.connect()
    client.add_event_callback(EVENT_PCX_COLLECTOR_REQUEST_TOPIC, CollectionEventCallback())
    client.add_event_callback(EVENT_PCE_REGISTRATION_TOPIC, RegistrationEventCallback())
    client.register_service_sync(info, 10)

    # Wait forever
    while True:
        # Process all collection requests that were received
        while collection_requests:
            crm = collection_requests.pop()

            # For each target get all associated PCEs
            # and task them with the collection
            for target in crm.targets:
                pce_ids = get_pces(target)
                for pce_id in pce_ids:
                    task_pce(crm, pce_id)

        time.sleep(1)
