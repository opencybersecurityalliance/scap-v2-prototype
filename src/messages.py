# NOTICE
#
# This software was produced for the U. S. Government under Basic Contract No.
# W56KGU-19-D-0004, and is subject to the Rights in Noncommercial Computer
# Software and Noncommercial Computer Software Documentation Clause
# 252.227-7014 (FEB 2012)
#
# (c) 2020 The MITRE Corporation. Approved for Public Release. Distribution Unlimited. Case Number 20-2258

import json
from enum import Enum

# Enumeration that defines the different message types used by the
# SCAP architecture
class MessageType(Enum):
    INITIATE_ASSESSMENT = 1
    REQUEST_ACKNOWLEDGEMENT = 2
    REPORT_RESULTS = 3
    CANCEL_ASSESSMENT = 4
    ARCHIVE_RESPONSE = 5
    QUERY = 6
    QUERY_RESULT = 7
    REGISTRATION = 8
    COLLECTION_REQUEST = 9

# Represents a message that sent by the application to the
# manager to begin the assessment of endpoints
class InitiateAssessmentMessage:
    def __init__(self, content = "", targeting = "",
                 oldest_results = "", latest_return = "", fresh_results = "",
                 collection_method = "", result_format_filters = "",
                 collection_parameters = "", transaction_id = "",
                 requestor_id = ""):
        self.message_type = MessageType.INITIATE_ASSESSMENT.value
        self.content = content
        self.targeting = targeting
        self.oldest_results = oldest_results
        self.latest_return = latest_return
        self.fresh_results = fresh_results
        self.collection_method = collection_method
        self.result_format_filters = result_format_filters
        self.collection_parameters = collection_parameters
        self.transaction_id = transaction_id
        self.requestor_id = requestor_id
        
    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.content = j["content"]
        self.targeting = j["targeting"]
        self.oldest_results = j["oldest_results"]
        self.latest_return = j["latest_return"]
        self.fresh_results = j["fresh_results"]
        self.collection_method = j["collection_method"]
        self.result_format_filters = j["result_format_filters"]
        self.collection_parameters = j["collection_parameters"]
        self.transaction_id = j["transaction_id"]
        self.requestor_id = j["requestor_id"]

    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["content"] = self.content
        j["targeting"] = self.targeting
        j["oldest_results"] = self.oldest_results
        j["latest_return"] = self.latest_return
        j["fresh_results"] = self.fresh_results
        j["collection_method"] = self.collection_method
        j["result_format_filters"] = self.result_format_filters
        j["collection_parameters"] = self.collection_parameters
        j["transaction_id"] = self.transaction_id
        j["requestor_id"] = self.requestor_id
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tContent: {}\n\tTargeting: {}\n\tOldest Results: {}\n\tLatest Return: {}\n\tFresh Results: {}\n\tCollection Method: {}\n\tResult Format Filters: {}\n\tCollection Parameters: {}\n\tTransaction ID: {}\n\tRequestor ID: {}".format(str(self.message_type), self.content, self.targeting, self.oldest_results, self.latest_return, self.fresh_results, self.collection_method, self.result_format_filters, self.collection_parameters, self.transaction_id, self.requestor_id)
        return s

# Represents a message sent by the Manager to the Collectors and
# PCXs to task them with the collection of endpoint information
class CollectorRequestMessage():
    def __init__(self, ids = "", targeting = "",
                 latest_return = "", collection_method = "",
                 result_format_filters = "", collection_parameters = "",
                 transaction_id = "", requestor_id = "", targets = ""):
        self.message_type = MessageType.COLLECTION_REQUEST.value
        self.ids = ids
        self.targeting = targeting
        self.latest_return = latest_return
        self.collection_method = collection_method
        self.result_format_filters = result_format_filters
        self.collection_parameters = collection_parameters
        self.transaction_id = transaction_id
        self.requestor_id = requestor_id
        self.targets = targets

    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.ids = j["ids"]
        self.targeting = j["targeting"]
        self.latest_return = j["latest_return"]
        self.collection_method = j["collection_method"]
        self.result_format_filters = j["result_format_filters"]
        self.collection_parameters = j["collection_parameters"]
        self.transaction_id = j["transaction_id"]
        self.requestor_id = j["requestor_id"]
        self.targets = j["targets"]
        
    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["ids"] = self.ids
        j["targeting"] = self.targeting
        j["latest_return"] = self.latest_return
        j["collection_method"] = self.collection_method
        j["result_format_filters"] = self.result_format_filters
        j["collection_parameters"] = self.collection_parameters
        j["transaction_id"] = self.transaction_id
        j["requestor_id"] = self.requestor_id
        j["targets"] = self.targets
        return json.dumps(j)                                     

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tIDs: {}\n\tTargeting: {}\n\tLatest Return: {}\n\tCollection Method: {}\n\tResult Format Filters: {}\n\tCollection Parameters: {}\n\tTransaction ID: {}\n\tRequestor ID: {}\n\tTargets: {}".format(str(self.message_type), self.ids, self.targeting, self.latest_return, self.collection_method, self.result_format_filters, self.collection_parameters, self.transaction_id, self.requestor_id, json.dumps(self.targets))
        return s

# Represents a message sent from the Manager to the Application
# that notifies the Application that the Manager received the
# request (initiate/cancel assessment) and is going to process it
class RequestAcknowledgementMessage:
    def __init__(self):
        self.message_type = MessageType.REQUEST_ACKNOWLEDGEMENT.value
        
    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.transaction_id = j["transaction_id"]

    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["transaction_id"] = self.transaction_id
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tTransaction ID: {}".format(str(self.message_type), self.transaction_id)
        return s

# Represents a message that stores the results of an assessment.
# This message is generated by Collectors and PCXs and sent to the
# Repository for storage and to the Application for further
# processing.
class ReportResultsMessage:
    def __init__(self, transaction_id="", requestor_id="", assessment_results="", target_id = "", collector_id ="", pcx_id="", pce_id="", timestamp=""):
        self.message_type = MessageType.REPORT_RESULTS.value
        self.transaction_id = transaction_id
        self.requestor_id = requestor_id
        self.assessment_results = assessment_results
        self.target_id = target_id
        self.collector_id = collector_id
        self.pcx_id = pcx_id
        self.pce_id = pce_id
        self.timestamp = timestamp

    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.transaction_id = j["transaction_id"]
        self.requestor_id = j["requestor_id"]
        self.assessment_results = j["assessment_results"]
        self.target_id = j["target_id"]
        self.collector_id = j["collector_id"]
        self.pcx_id = j["pcx_id"]
        self.pce_id = j["pce_id"]
        self.timestamp = j["timestamp"]
    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["transaction_id"] = self.transaction_id
        j["requestor_id"] = self.requestor_id
        j["assessment_results"] = self.assessment_results
        j["target_id"] = self.target_id
        j["collector_id"] = self.collector_id
        j["pcx_id"] = self.pcx_id
        j["pce_id"] = self.pce_id
        j["timestamp"] = self.timestamp
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tTransaction ID: {}\n\tRequestor ID: {}\n\tAssessment Results: {}\n\tTarget ID: {}\n\tCollector ID: {}\n\tPCX ID: {}\n\tPCE ID: {}\n\tTimestamp: {}".format(str(self.message_type), self.transaction_id, self.requestor_id, self.assessment_results, self.target_id, self.collector_id, self.pcx_id, self.pce_id, self.timestamp) 
        return s

# Represents a message sent by the Application to the Manager
# to cancel an assessment. 
class CancelAssessmentMessage:
    def __init__(self, transaction_id="", requestor_id=""):
        self.message_type = MessageType.CANCEL_ASSESSMENT.value
        self.transaction_id = transaction_id
        self.requestor_id = requestor_id
        
    def parse(self, m):
        j = json.loads(m)
	self.message_type = j["message_type"]
        self.transaction_id = j["transaction_id"]
        self.requestor_id = j["requestor_id"]
        
    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["transaction_id"] = self.transaction_id
        j["requestor_id"] = self.requestor_id
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tTransaction ID: {}\n\tRequestor ID: {}".format(self.message_type, self.transaction_id, self.requestor_id)
        return s

# Represents a message sent by the Application, Manager,
# Collectors, and PCXs to query information from the
# Repository.
class QueryMessage:
    def __init__(self, query=""):
        self.message_type = MessageType.QUERY.value
        self.query = query

    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.query = j["query"]

    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["query"] = self.query
        return json.dumps(j)

    def to_s(self):       
        s = "\n\tMessage Type: {}\n\tQuery: {}".format(str(self.message_type), self.query)  
        return s

# Represents a message sent by the Repository to the
# Application, Manager, Collectors, or PCXs with the
# results of a query.
class QueryResultMessage:
    def __init__(self, query = "", result = ""): 
        self.message_type = MessageType.QUERY_RESULT.value
        self.query = query
        self.result = result

    def	parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.query = j["query"]
        self.result = j["result"]

    def	to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["query"] = self.query
        j["result"] = self.result
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tQuery: {}\n\tResult: {}".format(str(self.message_type), self.query, self.result)
        return s

# Represents a message sent by PCEs (not mandatory),
# PCXs, and Collectors to register to the architecture.
# These messages are eventually stored in the Repository.
class RegistrationMessage:
    def __init__(self, pce_id = "", collector_id = "", pcx_id = "",  asset_info = "", pce_make = "", pce_model = "", target_id = "", pcx_make = "", pcx_model = "", collector_make = "", collector_model = "", supported_check_types = ""):
        self.message_type = MessageType.REGISTRATION.value
        self.pce_id = pce_id
        self.collector_id = collector_id
        self.pcx_id = pcx_id
        self.asset_info = asset_info
        self.pce_make = pce_make
        self.pce_model = pce_model
        self.target_id = target_id
        self.pcx_make = pcx_make
        self.pcx_model = pcx_model
        self.collector_make = collector_make
        self.collector_model = collector_model
        self.supported_check_types = supported_check_types

    def parse(self, m):
        j = json.loads(m)
        self.message_type = j["message_type"]
        self.pce_id = j["pce_id"]
        self.collector_id = j["collector_id"]
        self.pcx_id = j["pcx_id"]
        self.asset_info = j["asset_info"]
        self.pce_make = j["pce_make"]
        self.pce_model = j["pce_model"]
        self.target_id = j["target_id"]
        self.pcx_make = j["pcx_make"]
        self.pcx_model = j["pcx_model"]
        self.collector_make = j["collector_make"]
        self.collector_model = j["collector_model"]
        self.supported_check_types = j["supported_check_types"]
        
    def to_json(self):
        j = {}
        j["message_type"] = self.message_type
        j["pce_id"] = self.pce_id
        j["collector_id"] = self.collector_id
        j["pcx_id"] = self.pcx_id
        j["asset_info"] = self.asset_info
        j["pce_make"] = self.pce_make
        j["pce_model"] = self.pce_model
        j["target_id"] = self.target_id
        j["pcx_make"] = self.pcx_make
        j["pcx_model"] = self.pcx_model
        j["collector_make"] = self.collector_make
        j["collector_model"] = self.collector_model
        j["supported_check_types"] = self.supported_check_types
        return json.dumps(j)

    def to_s(self):
        s = "\n\tMessage Type: {}\n\tTarget ID: {}\n\tCollector ID: {}\n\tCollector Make: {}\n\tCollector Model: {}\n\tPCX ID: {}\n\tPCX Make: {}\n\tPCX Model: {}\n\tPCE ID: {}\n\tPCE Make: {}\n\tPCE Model: {}\n\tSupported Check Types: {}\n\tTarget ID: {}\n\tAsset Information: {}".format(str(self.message_type), self.target_id, self.collector_id, self.collector_make, self.collector_model, self.pcx_id, self.pcx_make, self.pcx_model, self.pce_id, self.pce_make, self.pce_model, json.dumps(self.supported_check_types), self.target_id, json.dumps(self.asset_info))
        return s
