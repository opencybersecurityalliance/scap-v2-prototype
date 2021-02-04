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
import json

from builtins import input as prompt
from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request, Response
from messages import InitiateAssessmentMessage, RequestAcknowledgementMessage, CancelAssessmentMessage
from messages import ReportResultsMessage, QueryMessage, QueryResultMessage

# Parse the Collector configuration file                                                                             
if len(sys.argv) == 1:
    print("Please specify a config file.")
    sys.exit()

collector_config = open(sys.argv[1])
j = json.load(collector_config)
APP_ID = j["application_id"]

# Topic to send assessment requests to the manager
SERVICE_INITIATE_ASSESSMENT_TOPIC = "/scap/service/assessment/initiate"

# Topic to send cancel assessment requests to the manager
SERVICE_CANCEL_ASSESSMENT_TOPIC = "/scap/service/assessment/cancel"

# Topic used to send queries to the repository
SERVICE_REPOSITORY_QUERY_TOPIC = "/scap/service/repository/query"

# Topic that this application listens on for assessment results
EVENT_ASSESSMENT_RESULTS_TOPIC = "/scap/event/assessment/results/" + APP_ID

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG)

# Stores the transaction ids of requests made by the application
transactions = []

# Create the client
with DxlClient(config) as client:

    # Display assessment results from initiate assessment requests
    def display_assessment_results(rrsm):
        logger.info("Displaying Assessment Results: %s", rrsm.to_s())

    # Display query results from query requests
    def display_query_results(qrm):
        logger.info("Displaying Query Results: %s", qrm.to_s())

    # Make an assessment request
    def request_assessment(iam):
        # Create a report request and send it to the manager
        req = Request(SERVICE_INITIATE_ASSESSMENT_TOPIC)
        req.payload = (iam.to_json()).encode()
        logger.info("Requesting report for %s:", iam.to_s())
        res = client.sync_request(req)

        # Extract and store the transaction id from the acknowledgement message
        if res.message_type != Message.MESSAGE_TYPE_ERROR:
            ram = RequestAcknowledgementMessage()
            ram.parse(res.payload.decode())
            logger.info("Application received response: %s", ram.to_s())
            transactions.append(ram.transaction_id)

    # Query the repository for information
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

    # Process incoming report results events
    class ReportResultsEventCallback(EventCallback):
        def on_event(self, event):
            # Parse and display the report results
            rrm = ReportResultsMessage()
            rrm.parse(event.payload.decode())
            display_assessment_results(rrm)

    # Connect to the message fabric and add listeners for report results and query results
    client.connect()
    client.add_event_callback(EVENT_ASSESSMENT_RESULTS_TOPIC, ReportResultsEventCallback())

    # Get input from the user as to what type of request they would like
    # to make to the SCAP architecture
    while True:
        print("Press 1 to perform an inventory")
        print("Press 2 to request a windows report")
        print("Press 3 to request a linux report")
        print("Press 4 to request a solaris report")
        print("Press 5 to request a macos report")
        print("Press 6 to request a ubuntu report")
        print("Press 7 to cancel an assessment")
        print("Press 8 to submit a query")
        print("Press 0 to quit")

        option = prompt("Enter option: ").strip()

        # Run an inventory scan
        if option == "1":
            m = InitiateAssessmentMessage("inventory", "*", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"d481281a-4d09-4564-a5a9-e86b46ad8e50\", \"check-type\": \"oval\"},{\"pce-id\": \"bd476f20-cfa4-4ff5-888a-0ba3a6bbb45d\", \"check-type\": \"oval\"},{\"pce-id\": \"7bc0df90-cdff-4c73-99ab-8539ca43afff\", \"check-type\": \"oval\"}, {\"pce-id\": \"c6048795-2d04-4142-806d-2c1d281c335c\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)

        # Assess a Windows system
        elif option == "2":
            m = InitiateAssessmentMessage("assess", "os == Windows 7", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"d481281a-4d09-4564-a5a9-e86b46ad8e50\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)

        # Assess a Linux system
        elif option == "3":
            m = InitiateAssessmentMessage("assess", "os == RHEL 7", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"bd476f20-cfa4-4ff5-888a-0ba3a6bbb45d\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)

        # Assess a Solaris system
        elif option == "4":
            m = InitiateAssessmentMessage("assess", "os == Solaris 11", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"7bc0df90-cdff-4c73-99ab-8539ca43afff\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)


        # Assess a MacOS system                                                                                    
        elif option == "5":
            m = InitiateAssessmentMessage("assess", "os == MacOS 10.14", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"c6048795-2d04-4142-806d-2c1d281c335c\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)

        # Assess a Ubuntu system
        elif option == "6":
            m = InitiateAssessmentMessage("assess", "os == Ubuntu 20.04", "<= 3 days", "06-15-2020", "true",
                                          "[{\"pce-id\": \"1fe4dc4a-37a6-4787-a47a-e27f28b08e43\", \"check-type\": \"oval\"}]",
                                          "oval", "full", "", APP_ID)
            request_assessment(m)

        # Cancel an assessment
        elif option == "7":
            # Send a cancel request to the manager
            req = Request(SERVICE_CANCEL_ASSESSMENT_TOPIC)
            print("Available assessments:")
            print(transactions)
            transaction_id = prompt("Enter transaction id: ").strip()
            m = CancelAssessmentMessage(transaction_id, APP_ID)
            req.payload = (m.to_json()).encode()
            res = client.sync_request(req)

            if res.message_type != Message.MESSAGE_TYPE_ERROR:
                ram = RequestAcknowledgementMessage()
                ram.parse(res.payload.decode())
                logger.info("Application received response: %s", ram.to_s())

        # Query the repository
        elif option == "8":
            # Send a query request to the manager with the imaginary
            # query "my new query"
            qrm = query_repository("special_query")
            display_query_results(qrm)

        # Quit the application
        elif option == "0":
            break

        else:
            logger.info("Invalid input: %s", option)
