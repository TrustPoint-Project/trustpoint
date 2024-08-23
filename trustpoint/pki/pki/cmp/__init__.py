"""
# CMP RA

## Overview

The CMP RA is designed for handling Certificate Management Protocol (CMP) messages, as specified in RFC 4210 and RFC 9453. This library is equipped to process CMP operations, including certificate requests, revocation requests, and general message handling. It supports multiple protection mechanisms, including signature-based and Password-Based Message Authentication Code (PBM) protections.

## Features

### CMP Request Handling
The library can process different types of CMP requests, including:

* **Initialization Request (IR)**: Used to request the issuance of an initial certificate.
* **Certification Request (CR)**: Used to request the issuance of a certificate.
* **Key Update Request (KUR)**: Used to request the update of an existing certificate's key.
* **Revocation Request (RR)**: Used to request the revocation of a certificate.
* **General Messages (GenM)**: Used for miscellaneous CMP messages that don't fall under the other categories.

### Protection Mechanisms
The library supports two primary protection mechanisms for securing CMP messages:

* **Signature-Based Protection**: Utilizes digital signatures (e.g., RSA or ECDSA) to authenticate and ensure the integrity of CMP messages. This mechanism involves the use of a private key for signing and a corresponding public key (certificate) for verification.
* **Password-Based Message Authentication Code (PBM)**: PBM protection uses a shared secret between the communicating entities to generate a HMAC.

"""

from . import builder
from .builder import *

from . import validator
from .validator import *

from . import messagehandler
from .messagehandler import *

from . import cert_template
from .cert_template import *

from . import errorhandling
from .errorhandling import *

from . import parsing
from .parsing import *

from . import protection
from .protection import *

from . import asn1_modules
from .asn1_modules import *

__all__ = []
# __all__.extend(builder.__all__)
# __all__.extend(validator.__all__)
# __all__.extend(messagehandler.__all__)
# __all__.extend(cert_template.__all__)
# __all__.extend(errorhandling.__all__)
# __all__.extend(parsing.__all__)
# __all__.extend(protection.__all__)
# __all__.extend(asn1_modules.__all__)