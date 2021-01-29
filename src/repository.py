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

from dxlclient.callbacks import RequestCallback, EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Request, Response
from dxlclient.service import ServiceRegistrationInfo
from messages import InitiateAssessmentMessage, ReportResultsMessage, QueryMessage, QueryResultMessage
from messages import RegistrationMessage, MessageType

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Topic that repository listens on for query requests                                                               
SERVICE_REPOSITORY_QUERY_TOPIC = "/scap/service/repository/query"

# Topic that repository listens for data to store                                                                   
EVENT_STORE_DATA_TOPIC = "/scap/event/data/store"

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Stores all transactions associated with an application
app_transactions = {}

# Stores all registered collectors
collectors = {}

# Stores all the targets identified on the network based on their operating system
targets = {}
targets["windows"] = []
targets["rhel"] = []
targets["solaris"] = []
targets["macos"] = []
targets["ubuntu"] = []

# Stores all the targets identified on the network
all_targets = []

# Create the client
with DxlClient(config) as client:

    # Store the initiate assessment request in the repository
    def store_request(iam):
        logger.info("Storing request: %s", iam.to_s())
        if iam.requestor_id in app_transactions.keys():
            app_transactions[iam.requestor_id].append(iam.transaction_id)
        else:
            app_transactions[iam.requestor_id] = [iam.transaction_id]

    # Store the report results in the repository
    def store_results(rrsm):
        logger.info("Storing results: %s", rrsm.to_s())

        if re.search(".*windows.*", rrsm.assessment_results):
            if rrsm.target_id not in targets["windows"]:
                targets["windows"].append(rrsm.target_id)
        elif re.search(".*rhel.*", rrsm.assessment_results):
            if rrsm.target_id not in targets["rhel"]:
                targets["rhel"].append(rrsm.target_id)
        elif re.search(".*solaris.*", rrsm.assessment_results):
            if rrsm.target_id not in targets["solaris"]:
                targets["solaris"].append(rrsm.target_id)
        elif re.search(".*macos.*", rrsm.assessment_results):
            if rrsm.target_id not in targets["macos"]:
                targets["macos"].append(rrsm.target_id)
        elif re.search(".*ubuntu.*", rrsm.assessment_results):
            if rrsm.target_id not in targets["ubuntu"]:
                targets["ubuntu"].append(rrsm.target_id)

    # Store the assets in the repository                                                                            
    def store_assets(rm):
        logger.info("Storing assets: %s", rm.to_s())

        if rm.target_id in collectors.keys():
            if rm.collector_id not in collectors[rm.target_id]:
                collectors[rm.target_id].append(rm.collector_id)
        else:
            collectors[rm.target_id] = [rm.collector_id]

            if rm.target_id not in all_targets:
                all_targets.append(rm.target_id)

    # Store arbitrary data in the repository
    def store_arbitrary_data(data):
        logger.info("Storing arbitrary data: %s", data)

    # Execute the query against the repository. Return imaginary
    # "query results"
    def execute_query(query):
        logger.info("Executing query: %s", query)

        if query == "windows_results":
            return ""  # No previous results
        elif query == "rhel_results":
            return "previous rhel results"
        elif query == "solaris_results":
            return ""  # No previous results
        elif query == "macos_results":
            return ""  # No previous results
        elif query == "ubuntu_results":
            return ""  # No previous results
        elif query == "windows_rhel_solaris_macos_ubuntu_results":
            return ""  # No previous results
        elif query == "windows_targets":
            return targets["windows"]
        elif query == "rhel_targets":
            return targets["rhel"]
        elif query == "solaris_targets":
            return targets["solaris"]
        elif query == "macos_targets":
            return targets["macos"]
        elif query == "ubuntu_targets":
            return targets["ubuntu"]
        elif query == "windows_rhel_solaris_macos_ubuntu_targets":
            return all_targets

        # Get in-scope collectors based on the list of target
        # identifiers
        elif re.search("targets_.*", query):
            in_scope_collectors = []
            target_list = json.loads(query.split("_")[1])
            for t in target_list:
                for c in collectors[t]:
                    if c not in in_scope_collectors:
                        in_scope_collectors.append(c)
            return in_scope_collectors
        elif query == "special_query":
            return "my_special_results"
        else:
            return ""

    # Process incoming query requests from the manager
    class QueryRequestCallback(RequestCallback):
        def on_request(self, request):
            
            # Parse the query message and execute the query
            # against the repository
            qm = QueryMessage()
            qm.parse(request.payload.decode())
            results = execute_query(qm.query)

            # Send query result back to the requesting component
            response = Response(request)
            qrm = QueryResultMessage(qm.query, results)
            response.payload = (qrm.to_json()).encode()
            logger.info("Sending query results: " + qrm.to_s())
            client.send_response(response)

    # Process incoming storage requests
    class StoreDataEventCallback(EventCallback):
        def on_event(self, event):

            j = json.loads(event.payload.decode())
            message_type = j["message_type"]

            if message_type == MessageType.INITIATE_ASSESSMENT.value:
                iam = InitiateAssessmentMessage()
                iam.parse(event.payload.decode())
                store_request(iam)
            elif message_type == MessageType.REPORT_RESULTS.value:
                rrsm = ReportResultsMessage()
                rrsm.parse(event.payload.decode())
                store_results(rrsm)
            elif message_type == MessageType.REGISTRATION.value:
                rm = RegistrationMessage()
                rm.parse(event.payload.decode())
                store_assets(rm)
            else:
                store_arbitrary_data(event.payload.decode())

    # Prepare service registration information                                                                      
    info = ServiceRegistrationInfo(client, "/scap/repository")

    # Connect to the message fabric and add listeners for query requests and
    # storage requests
    client.connect()
    client.add_event_callback(EVENT_STORE_DATA_TOPIC, StoreDataEventCallback())
    info.add_topic(SERVICE_REPOSITORY_QUERY_TOPIC, QueryRequestCallback())
    client.register_service_sync(info, 10)

    # Wait forever
    while True:
        time.sleep(1)
