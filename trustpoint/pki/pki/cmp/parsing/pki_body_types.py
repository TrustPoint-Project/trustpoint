from pyasn1_modules import rfc4210, rfc2511, rfc2314
from pyasn1.type import univ

from . import UnacceptedPolicy

class PKIBodyTypes:
    """
    A class to manage CMP body types and their corresponding
    request and response messages based on various RFCs.

    Attributes:
        request_map (dict): A dictionary mapping request names to their respective classes,
                            friendly names, and support status.
        response_relation_map (dict): A dictionary mapping request short names to their
                                      corresponding response short names.
        _valid_request (bool): Indicates whether the current request is valid.
        _request_class (Any): The class of the current request.
        _request_friendly_name (str): The friendly name of the current request.
        _response_short_name (str): The short name of the response for the current request.
        _response_class (Any): The class of the response for the current request.
        _response_friendly_name (str): The friendly name of the response for the current request.
        _supported (bool): Indicates whether the current request type is supported.
        _request_short_name (str): The short name of the current request.
    """
    def __init__(self):
        self.request_map = {
            "ir": (rfc2511.CertReqMessages, "CertReqMessages", True),  # Initialization Req
            "ip": (rfc4210.CertRepMessage, "CertRepMessage", True),  # Initialization Resp
            "cr": (rfc2511.CertReqMessages, "CertReqMessages", True),  # Certification Req
            "cp": (rfc4210.CertRepMessage, "CertRepMessage", True),  # Certification Resp
            "p10cr": (rfc2314.CertificationRequest, "CertificationRequest", False),  # PKCS #10 Cert. Req.
            "popdecc": (rfc4210.POPODecKeyChallContent, "POPODecKeyChallContent", False),  # pop Challenge
            "popdecr": (rfc4210.POPODecKeyRespContent, "POPODecKeyRespContent", False),  # pop Response
            "kur": (rfc2511.CertReqMessages, "CertReqMessages", True),  # Key Update Request
            "kup": (rfc4210.CertRepMessage, "CertRepMessage", True),  # Key Update Response
            "krr": (rfc2511.CertReqMessages, "CertReqMessages", False),  # Key Recovery Req
            "krp": (rfc4210.KeyRecRepContent, "KeyRecRepContent", False),  # Key Recovery Resp
            "rr": (rfc4210.RevReqContent, "RevReqContent", True),  # Revocation Request
            "rp": (rfc4210.RevRepContent, "RevRepContent", True),  # Revocation Response
            "ccr": (rfc2511.CertReqMessages, "CertReqMessages", False),  # Cross-Cert. Request
            "ccp": (rfc4210.CertRepMessage, "CertRepMessage", False),  # Cross-Cert. Resp
            "ckuann": (rfc4210.CAKeyUpdAnnContent, "CAKeyUpdAnnContent", False),  # CA Key Update Ann.
            "cann": (rfc4210.CertAnnContent, "CertAnnContent", False),  # Certificate Ann.
            "rann": (rfc4210.RevAnnContent, "RevAnnContent", False),  # Revocation Ann.
            "crlann": (rfc4210.CRLAnnContent, "CRLAnnContent", False),  # CRL Announcement
            "pkiconf": (rfc4210.PKIConfirmContent, "PKIConfirmContent", False),  # Confirmation
            "nested": (rfc4210.NestedMessageContent, "NestedMessageContent", False),  # Nested Message
            "genm": (rfc4210.GenMsgContent, "GenMsgContent", True),  # General Message
            "gen": (rfc4210.GenRepContent, "GenRepContent", True),  # General Response
            "error": (rfc4210.ErrorMsgContent, "ErrorMsgContent", True),  # Error Message
            "certConf": (rfc4210.CertConfirmContent, "CertConfirmContent", False),  # Certificate confirm
            "pollReq": (rfc4210.PollReqContent, "PollReqContent", False),  # Polling request
            "pollRep": (rfc4210.PollRepContent, "PollRepContent", False)  # Polling response
        }

        self.response_relation_map = {
            "ir": "ip",
            "cr": "cp",
            "kur": "kup",
            "rr": "rp",
            "genm": "gen",
            "certConf": "pkiconf"
        }

        self._valid_request = True
        self._request_class = None
        self._request_friendly_name = None
        self._response_short_name = None
        self._response_class = None
        self._response_friendly_name = None
        self._request_short_name = None

    def add_explicit_tag(self, class_instance, tag_number):
        """
        Adds an explicit tag to the given class instance.

        :param class_instance: The class instance to modify.
        :param tag_number: The tag number to add.
        :return: The modified class instance.
        """
        return class_instance().subtype(
            explicitTag=univ.tag.Tag(univ.tag.tagClassContext, univ.tag.tagFormatConstructed, tag_number)
        )

    def get_response(self, input_name: str):
        """
        Returns the class, friendly name, short name of the response, class of the response,
        and the friendly name of the response based on the given input.

        :param input_name: str, the short or long name of the request
        :raises UnacceptedPolicy: If the request is not valid or supported.
        """
        # Check if input is short name
        request_info = self.request_map.get(input_name)

        if not request_info:
            # Check if input is friendly name
            request_info = next((v for k, v in self.request_map.items() if v[1] == input_name), None)
            if not request_info:
                self._valid_request = False
                request_info = [None, None, False]
            short_name = next(k for k, v in self.request_map.items() if v == request_info)
        else:
            short_name = input_name

        self._request_class, self._request_friendly_name, self._supported = request_info
        self._response_short_name = self.response_relation_map.get(short_name,
                                                                   "No predefined response")

        tag_number_request = list(self.request_map.keys()).index(short_name)
        self._request_class = self.add_explicit_tag(self._request_class, tag_number_request)
        self._request_short_name = short_name

        if self._response_short_name == "No predefined response":
            self._response_friendly_name = "N/A"
            self._response_class = None
        else:
            self._response_friendly_name = self.request_map[self._response_short_name][1]
            self._response_class = self.request_map[self._response_short_name][0]
            tag_number_response = list(self.request_map.keys()).index(self._response_short_name)
            self._response_class = self.add_explicit_tag(self._response_class, tag_number_response)

        if not self._valid_request:
            raise UnacceptedPolicy("Not a valid request")

        if not self._supported:
            raise UnacceptedPolicy("Not a supported function")

    def _set_error_response(self):
        """
        Sets the response attributes to represent an error response.
        """
        self._response_short_name = "error"
        tag_number_response = list(self.request_map.keys()).index(self._response_short_name)
        self._response_class = rfc4210.ErrorMsgContent
        self._response_class = self.add_explicit_tag(self._response_class, tag_number_response)
        self._response_friendly_name = "ErrorMsgContent"

    @property
    def request_class(self):
        """Returns the class of the current request."""
        return self._request_class

    @property
    def request_friendly_name(self):
        """Returns the friendly name of the current request."""
        return self._request_friendly_name

    @property
    def response_short_name(self):
        """Returns the short name of the response for the current request."""
        return self._response_short_name

    @property
    def response_class(self):
        """Returns the class of the response for the current request."""
        return self._response_class

    @property
    def response_friendly_name(self):
        """Returns the friendly name of the response for the current request."""
        return self._response_friendly_name

    @property
    def supported(self):
        """Returns whether the current request type is supported."""
        return self._supported

    @property
    def valid_request(self):
        """Returns whether the current request is valid."""
        return self._valid_request

    @property
    def request_short_name(self):
        """Returns the short name of the current request."""
        return self._request_short_name

    def prettyPrint(self):
        """
        Returns a string representation of the current state of the PKIBodyTypes instance.

        :return: str, formatted string representing the current state
        """
        return (
            f"PKIBodyTypes(\n"
            f"  request_short_name          ={self.request_short_name},\n"
            f"  request_class               ={type(self.request_class)},\n"
            f"  request_friendly_name       ={self.request_friendly_name},\n"
            f"  response_short_name         ={self.response_short_name},\n"
            f"  response_class              ={type(self.response_class)},\n"
            f"  response_friendly_name      ={self.response_friendly_name},\n"
            f"  supported                   ={self.supported},\n"
            f"  valid_request               ={self.valid_request}\n"
            f")"
        )

