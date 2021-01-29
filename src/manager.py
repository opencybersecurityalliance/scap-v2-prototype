# NOTICE                                                                                                 
#                                                                                                       
# This software was produced for the U. S. Government under Basic Contract No.                           
# W56KGU-19-D-0004, and is subject to the Rights in Noncommercial Computer                               
# Software and Noncommercial Computer Software Documentation Clause                                      
# 252.227-7014 (FEB 2012)                                                                              
#                                                                                                       
# (c) 2020 The MITRE Corporation. Approved for Public Release. Distribution Unlimited. Case Number 20-2258

from __future__ import absolute_import
from __future__ import print_function
import logging
import os
import sys
import time
import uuid
import json
import re

from dxlclient.callbacks import RequestCallback, ResponseCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request, Response
from dxlclient.service import ServiceRegistrationInfo
from dxlclient.message import Event
from messages import InitiateAssessmentMessage, RequestAcknowledgementMessage, CancelAssessmentMessage
from messages import ReportResultsMessage, MessageType, QueryMessage, QueryResultMessage, CollectorRequestMessage

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Topic that manager listens on for assessment requests
SERVICE_INITIATE_ASSESSMENT_TOPIC = "/scap/service/assessment/initiate"

# Topic that manager listens on for cancel requests TODO: May go away
SERVICE_CANCEL_ASSESSMENT_TOPIC = "/scap/service/assessment/cancel"

# Topic used to send collection requests to the collector
EVENT_COLLECTOR_REQUEST_TOPIC = "/scap/event/collector/request"

# Topic used to send queries to the repository
SERVICE_REPOSITORY_QUERY_TOPIC = "/scap/service/repository/query"

# Base topic for application assessment results
EVENT_ASSESSMENT_RESULTS_TOPIC = "/scap/event/assessment/results"

# Topic that repository listens for data to store                                                                
EVENT_STORE_DATA_TOPIC = "/scap/event/data/store"

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Stores initiate assessment requests for processing
assessment_requests = []

# Stores transactions of ongoing assessments for each application
transactions = {}

# Stores transactions associated with targets so we know where
# to send cancellation requests
transactions_targets = {}

# Create the client
with DxlClient(config) as client:

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

    # Send collection results to the appropriate application        
    def send_collection_results_event(rrsm):
        send_event(EVENT_ASSESSMENT_RESULTS_TOPIC + "/" + rrsm.requestor_id, rrsm.to_json())

    # Store data in the repository
    def store_data(m):
        logger.info("Storing data in the repository: %s", m.to_s())
        send_event(EVENT_STORE_DATA_TOPIC, m.to_json())

    # Task specific collector with collection request
    def task_collector(crm, collector):
        logger.info("Tasking collector %s with request: %s", collector, crm.to_s())
        send_event(EVENT_COLLECTOR_REQUEST_TOPIC+"/"+collector, crm.to_json())

    # Send event to the specified topic                                                                            
    def send_event(topic, m):
        event = Event(topic)
        event.payload = m.encode()
        client.send_event(event)

    # Acknowledge incoming requests with an acknowledgement message
    # and assign a transaction id
    def acknowledge_request(request):
        # Prepare response and assign a new transaction
        # id 
        res = Response(request)
        rm = RequestAcknowledgementMessage()
        rm.transaction_id = str(uuid.uuid4())
        res.payload = (rm.to_json()).encode()

        # Send the request acknowledgement to the application
        # in reponse to the request and return the transaction
        # id
        logger.info("Sending request acknowlegement: %s", rm.to_s())
        client.send_response(res)
        return rm.transaction_id

    # Parse the content and extract the check identifiers
    # If there is content just extract imaginary identifiers
    # 1, 2, and 3. Otherwise, it should remain the empty string
    # because it represents a cancel assessment request
    def get_ids(content):
        ids = ""
        if content == "inventory":
            ids = "1,2,3"
        elif content == "assess":
            ids = "4,5,6"
        elif content == "remaining_request":
            ids = "7,8,9"
        return ids

    # Determine if the report request represents on-going monitoring
    # or a point-in-time assessment. Only support point-in-time                                                     
    # assessments for now.                        
    def is_point_in_time_assessment(iam):
        if iam.content == "assess" or iam.content == "inventory":
            return True
        else:
            return False

    # Build repository query based on targeting information and the
    # type of information that is needed
    def query_builder(targeting, option):
        query = ""
        if re.search(".*[Ww][Ii][Nn][Dd][Oo][Ww][Ss].*", targeting):
            query = "windows"
        elif re.search(".*[Rr][Hh][Ee][Ll].*", targeting):
            query = "rhel"
        elif re.search(".*[Ss][Oo][Ll][Aa][Rr][Ii][Ss].*", targeting):
            query = "solaris"
        elif re.search(".*[Mm][Aa][Cc][Oo][Ss].*", targeting):
            query = "macos"
        elif re.search(".*[Uu][Bb][Uu][Nn][Tt][Uu].*", targeting):
            query = "ubuntu"
        elif re.search("\*", targeting):
            query = "windows_rhel_solaris_macos_ubuntu"
        else:
            return None

        return query + "_" + option

    # Get previous assessment results from the repository                                                              
    def get_previous_results(iam, targets):
        logger.info("Searching for previous results")

        query = query_builder(iam.targeting, "results")

        # Query the repository and filter based on oldest results,
        # result_format_filters, collection_method, and targeting
        # properties of the report request message
        qrm = query_repository(query)

        if qrm.result == "":
            logger.info("Found: " + str(None))
            return None
        else:
            rrsm = ReportResultsMessage(iam.transaction_id, iam.requestor_id, "", "", qrm.result)
            logger.info("Found: " + qrm.result)
            return rrsm

    # Get applicable/undetermined targets from the repository
    def get_applicable_targets(iam):
        logger.info("Searching for applicable/undetermined targets")

        query = query_builder(iam.targeting, "targets")

        # Query the repository for applicable and undetermined
        # assets
        qrm = query_repository(query)
        logger.info("Found: " + str(qrm.result))
        return qrm.result

    # Get in scope collectors based on targets from the repository
    def get_collectors(targets):
        logger.info("Searching for in scope collectors")

        query = "targets_" + json.dumps(targets)

        # Query the repository for in scope collectors
        # based on specified targets
        qrm = query_repository(query)
        logger.info("Found: " + str(qrm.result))
        return qrm.result

    # Task the collectors with the initiate assessment request
    def task_collectors(iam, targets, collectors):
        logger.info("Tasking the collectors %s with collection request", collectors)

        # Extract the check identifiers from the content and create
        # a collection request using the information from the initiate
        # assessment request
        ids = get_ids(iam.content)
        crm = CollectorRequestMessage(ids, iam.targeting, iam.latest_return,
                                      iam.collection_method, iam.result_format_filters,
                                      iam.collection_parameters, iam.transaction_id,
                                      iam.requestor_id, targets)

        # Send collector request events to the appropriate
        # collectors
        for collector in collectors:
            task_collector(crm, collector)

    # Using the previously collected results and the initiate
    # assessment request to determine what checks are remaining
    # from the report request. Just pass the request through for now
    def get_remaining_request(previous_results, iam):
        # Assume the previous results cover the entire assessment
        # so just return None
        if previous_results == None:
            return iam
        else:
            iam.content = "remaining_request"
            return iam

    # Process incoming assessments from applications
    class InitiateAssessmentCallback(RequestCallback):
        def on_request(self, request):
            # Acknowledge the initiate assessment request
            # and get a new transaction id
            transaction_id = acknowledge_request(request)

            # Parse the initiate assessment request message
            # and set the transaction id with the new
            # transaction id
            iam = InitiateAssessmentMessage()
            iam.parse(request.payload.decode())
            iam.transaction_id = transaction_id

            logger.info("Manager recieved initiate assessment request: %s", iam.to_s())

            # Add to the list of active assessment transactions
            if iam.requestor_id in transactions.keys():
                transactions[iam.requestor_id].append(transaction_id)
            else:
                transactions[iam.requestor_id] = [transaction_id]

            # Append the initiate assessment request to the list
            # of requests that need to be processed
            assessment_requests.append(iam)

    # Process incoming cancel assessment messages from the application
    class CancelAssessmentCallback(RequestCallback):
        def on_request(self, request):
            # Parse cancel assessment message
            cam = CancelAssessmentMessage()
            cam.parse(request.payload.decode())
            logger.info("Manager received cancel assessment request: %s", cam.to_s())

            # Check to make sure it came from the application
            # that originally requested the assessment. If it
            # is not, just ignore the message
            if cam.requestor_id in transactions.keys() and cam.transaction_id in transactions[cam.requestor_id]:
                assessment_requests.append(cam)
            # Cancel request didn't come from originating application so ignore
            else:
                logger.info("Ignoring cancel request " + cam.transaction_id + " for application " + cam.requestor_id)

            # Send request acknowledgement message with the transaction
            # id that was cancelled 
            res = Response(request)
            ram = RequestAcknowledgementMessage()
            ram.transaction_id = cam.transaction_id
            res.payload = (ram.to_json()).encode()
            client.send_response(res)

    # Prepare service registration information
    info = ServiceRegistrationInfo(client, "/scap/manager")

    # Have manager provide assessment request, cancel assessment, and query services
    info.add_topic(SERVICE_INITIATE_ASSESSMENT_TOPIC, InitiateAssessmentCallback())
    info.add_topic(SERVICE_CANCEL_ASSESSMENT_TOPIC, CancelAssessmentCallback())

    # Connect to the message fabric and register the service
    client.connect()
    client.register_service_sync(info, 10)

    # Wait forever
    while True:
        # Process all initiate assessment requests that were received 
        while assessment_requests:
            ar = assessment_requests.pop(0)

            if ar.message_type == MessageType.CANCEL_ASSESSMENT.value:

                iam = InitiateAssessmentMessage()
                iam.transaction_id = ar.transaction_id
                iam.requestor_id = ar.requestor_id

                targets = transactions_targets[ar.transaction_id]

                # Query the repository for in scope collectors                                                      
                collectors = get_collectors(targets)

                # Task the in scope collectors
                task_collectors(iam, targets, collectors)
            else:
                # Store the initiate assessment request in the repository 
                store_data(ar)

                # Query the repository for applicable targets                                                       
                targets = get_applicable_targets(ar)

                # Store targets associated with the transaction_id
                transactions_targets[ar.transaction_id] = targets

                # If point-in-time assessment, get any previous results from                                       
                # the database                                                                                     
                previous_results = None
                if is_point_in_time_assessment(ar):
                    previous_results = get_previous_results(ar, targets)

                # If there are previous results, send the results to the
                # application
                if previous_results != None:
                    # Send results to the requesting application
                    send_collection_results_event(previous_results)

                # Based on previous results determine what is left                                                  
                # and task the collector                                                                           
                rr_ar = get_remaining_request(previous_results, ar)

                # Query the repository for in scope collectors
                collectors = get_collectors(targets)

                # Task the in scope collectors
                task_collectors(rr_ar, targets, collectors)

        time.sleep(1)
