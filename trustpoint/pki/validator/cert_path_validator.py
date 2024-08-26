from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timezone
from typing import List, Set, Optional, Dict, Tuple

class PathValidationError(Exception):
    """Custom exception for path validation errors."""
    pass

class PathValidator:
    def __init__(self,
                 trust_anchor: x509.Certificate,
                 user_initial_policy_set: Set[str] = {"any-policy"},
                 initial_policy_mapping_inhibit: bool = False,
                 initial_explicit_policy: bool = False,
                 initial_any_policy_inhibit: bool = False,
                 initial_permitted_subtrees: Optional[Dict[str, List[str]]] = None,
                 initial_excluded_subtrees: Optional[Dict[str, List[str]]] = None):
        """
        Initialize the path validator with a trusted root certificate and other path validation inputs.

        :param trust_anchor: The trusted root certificate (X.509 certificate)
        :param user_initial_policy_set: Set of certificate policy identifiers.
        :param initial_policy_mapping_inhibit: Indicates if policy mapping is allowed.
        :param initial_explicit_policy: Indicates if the path must be valid for at least one policy.
        :param initial_any_policy_inhibit: Indicates if anyPolicy OID should be processed.
        :param initial_permitted_subtrees: Specifies the subtrees within which subject names must fall.
        :param initial_excluded_subtrees: Specifies the subtrees within which subject names must not fall.
        """
        self.trust_anchor = trust_anchor
        self.user_initial_policy_set = user_initial_policy_set
        self.initial_policy_mapping_inhibit = initial_policy_mapping_inhibit
        self.initial_explicit_policy = initial_explicit_policy
        self.initial_any_policy_inhibit = initial_any_policy_inhibit
        self.initial_permitted_subtrees = initial_permitted_subtrees or {}
        self.initial_excluded_subtrees = initial_excluded_subtrees or {}

        # Initialize state variables
        self.valid_policy_tree = self._initialize_valid_policy_tree()
        self.permitted_subtrees = initial_permitted_subtrees
        self.excluded_subtrees = initial_excluded_subtrees
        self.explicit_policy = 0 if initial_explicit_policy else None
        self.inhibit_anyPolicy = 0 if initial_any_policy_inhibit else None
        self.policy_mapping = 0 if initial_policy_mapping_inhibit else None
        self.working_public_key_algorithm = trust_anchor.signature_algorithm_oid
        self.working_public_key = trust_anchor.public_key()
        self.working_public_key_parameters = trust_anchor.public_key().public_numbers() if hasattr(
            trust_anchor.public_key(), 'public_numbers') else None
        self.working_issuer_name = trust_anchor.subject
        self.max_path_length = None

    def validate(self, cert_chain: List[x509.Certificate], current_time: Optional[datetime] = None) -> Tuple[
        bool, Optional[Dict]]:
        """
        Validate a certificate chain.

        :param cert_chain: List of X.509 certificates starting from the target certificate to the root.
        :param current_time: The current date and time for validation.
        :return: True if the path is valid, raises PathValidationError otherwise.
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        n = len(cert_chain)
        if self.max_path_length is None:
            self.max_path_length = n

        # Step 1: Initialization
        self._initialize(cert_chain)

        # Step 2: Basic Certificate Processing (for each certificate in the chain)
        for i, cert in enumerate(cert_chain):
            print(cert)
            self._process_certificate(cert, i, n, current_time)


            # Step 3: Preparation for the Next Certificate (i+1)
            if i < n - 1:
                self._prepare_for_next_certificate(cert, i, n)

        # Step 4: Wrap-Up Procedure (for certificate n)
        self._wrap_up_procedure(cert_chain[-1], n)

        # Step 5: Outputs
        return self._outputs()

    def _initialize(self, cert_chain: List[x509.Certificate]):
        """
        Initialize path validation state.

        :param cert_chain: List of X.509 certificates.
        """
        n = len(cert_chain)

        # Explicit Policy: set to n+1 if initial_explicit_policy is not set
        if self.explicit_policy is None:
            self.explicit_policy = n + 1

        # Inhibit anyPolicy: set to n+1 if initial_any_policy_inhibit is not set
        if self.inhibit_anyPolicy is None:
            self.inhibit_anyPolicy = n + 1

        # Policy Mapping: set to n+1 if initial_policy_mapping_inhibit is not set
        if self.policy_mapping is None:
            self.policy_mapping = n + 1

        if len(cert_chain) == 0:
            raise PathValidationError("Certificate chain is empty.")
        if len(set(cert_chain)) != len(cert_chain):
            raise PathValidationError("Certificate chain contains duplicate certificates.")

    def _initialize_valid_policy_tree(self):
        """
        Initialize the valid policy tree to its starting state.

        :return: The initial valid policy tree.
        """
        return {
            'valid_policy': 'anyPolicy',
            'qualifier_set': set(),
            'expected_policy_set': {'anyPolicy'}
        }

    def _process_certificate(self, cert: x509.Certificate, i: int, n: int, current_time: datetime):
        """
        Process the i-th certificate in the certification path.

        :param cert: The X.509 certificate to process.
        :param i: The index of the certificate in the chain.
        :param n: The total number of certificates in the chain.
        :param current_time: The current date and time for validation.
        """
        # (a) Verify the basic certificate information
        self._verify_signature(cert, self.working_public_key)
        self._check_certificate_validity(cert, current_time)

        if cert.issuer != self.working_issuer_name:
            raise PathValidationError(f"Issuer mismatch at certificate {i + 1}.")

        # (b) Name Constraints: Check permitted subtrees
        if not (cert.subject == cert.issuer and i == n - 1):  # Skip for self-issued non-final certs
            self._check_name_constraints(cert, self.permitted_subtrees, True)

        # (c) Name Constraints: Check excluded subtrees
        if not (cert.subject == cert.issuer and i == n - 1):  # Skip for self-issued non-final certs
            self._check_name_constraints(cert, self.excluded_subtrees, False)

        # (d) Policy Processing
        self._process_certificate_policies(cert, i, n)

        # (f) Explicit Policy
        if self.explicit_policy is not None and self.explicit_policy <= 0 and self.valid_policy_tree is None:
            raise PathValidationError("Explicit policy required but no valid policies found.")

    def _prepare_for_next_certificate(self, cert: x509.Certificate, i: int, n: int):
        """
        Prepare for processing the next certificate in the path (i+1).

        :param cert: The X.509 certificate just processed (certificate i).
        :param i: The index of the current certificate in the chain.
        :param n: The total number of certificates in the chain.
        """
        # Handle policy mappings, if any
        policy_mappings_ext = self._get_unrecognized_extension(cert, ExtensionOID.POLICY_MAPPINGS)
        if policy_mappings_ext:
            self._process_policy_mappings(policy_mappings_ext, i)

        # (c) Assign the certificate subject name to working_issuer_name
        self.working_issuer_name = cert.subject

        # (d) Assign the certificate subjectPublicKey to working_public_key
        self.working_public_key = cert.public_key()

        # (e) and (f) Update the working_public_key_algorithm and parameters
        self.working_public_key_algorithm = cert.signature_algorithm_oid
        self.working_public_key_parameters = cert.public_key().public_numbers() if hasattr(cert.public_key(),
                                                                                           'public_numbers') else None

        # Handle name constraints
        name_constraints_ext = self._get_extension(cert, x509.NameConstraints)
        if name_constraints_ext:
            self._process_name_constraints(name_constraints_ext)

        # Update explicit_policy, policy_mapping, and inhibit_anyPolicy
        if not cert.subject == cert.issuer:  # Skip for self-issued certs
            if self.explicit_policy is not None and self.explicit_policy > 0:
                self.explicit_policy -= 1
            if self.policy_mapping is not None and self.policy_mapping > 0:
                self.policy_mapping -= 1
            if self.inhibit_anyPolicy is not None and self.inhibit_anyPolicy > 0:
                self.inhibit_anyPolicy -= 1

        # Handle policy constraints and inhibitAnyPolicy extensions
        policy_constraints_ext = self._get_extension(cert, x509.PolicyConstraints)
        if policy_constraints_ext:
            self._process_policy_constraints(policy_constraints_ext)

        inhibit_any_policy_ext = self._get_extension(cert, x509.InhibitAnyPolicy)
        if inhibit_any_policy_ext:
            self._process_inhibit_any_policy(inhibit_any_policy_ext)

        # Verify that the basicConstraints extension is present and cA is set to TRUE
        self._check_basic_constraints(cert)

        # Handle path length constraints
        if not cert.subject == cert.issuer:  # Skip for self-issued certs
            if self.max_path_length is not None:
                if self.max_path_length <= 0:
                    raise PathValidationError("max_path_length constraint violated.")
                self.max_path_length -= 1

        basic_constraints_ext = self._get_extension(cert, x509.BasicConstraints)
        if basic_constraints_ext and basic_constraints_ext.path_length is not None and self.max_path_length is not None:
            self.max_path_length = min(self.max_path_length, basic_constraints_ext.path_length)

        # Verify key usage
        key_usage_ext = self._get_extension(cert, x509.KeyUsage)
        if key_usage_ext and not key_usage_ext.key_cert_sign:
            raise PathValidationError("Key usage does not permit certificate signing.")

        # Recognize and process any other critical extensions
        self._process_critical_extensions(cert)

    def _get_extension(self, cert: x509.Certificate, extension_class):
        """
        Retrieve an extension by its class.
        :param cert: The X.509 certificate.
        :param extension_class: The class of the extension to retrieve (e.g., x509.NameConstraints).
        :return: The extension object if found, otherwise None.
        """
        try:
            return cert.extensions.get_extension_for_class(extension_class).value
        except x509.ExtensionNotFound:
            return None

    def _get_unrecognized_extension(self, cert: x509.Certificate, oid: ExtensionOID):
        """
        Retrieve an unrecognized extension by its OID.
        :param cert: The X.509 certificate.
        :param oid: The OID of the extension to retrieve.
        :return: The raw extension if found, otherwise None.
        """
        try:
            ext = cert.extensions.get_extension_for_oid(oid)
            return ext.value
        except x509.ExtensionNotFound:
            return None

    def _wrap_up_procedure(self, cert: x509.Certificate, n: int):
        """
        Wrap-up procedure for the final certificate in the path (certificate n).

        :param cert: The final certificate in the chain (certificate n).
        :param n: The total number of certificates in the chain.
        """
        # (a) Decrement explicit_policy if it's not 0
        if self.explicit_policy is not None and self.explicit_policy > 0:
            self.explicit_policy -= 1

        # (b) Process the policy constraints extension
        try:
            policy_constraints_ext = cert.extensions.get_extension_for_class(x509.PolicyConstraints).value
            if policy_constraints_ext.require_explicit_policy == 0:
                self.explicit_policy = 0
        except x509.ExtensionNotFound:
            pass

        # (c), (d), and (e) Update working_public_key, working_public_key_parameters, and algorithm
        self.working_public_key = cert.public_key()
        self.working_public_key_algorithm = cert.signature_algorithm_oid
        self.working_public_key_parameters = cert.public_key().public_numbers() if hasattr(cert.public_key(),
                                                                                           'public_numbers') else None

        # (f) Recognize and process any other critical extensions in the final certificate
        self._process_critical_extensions(cert)

        # (g) Calculate the intersection of valid_policy_tree and user_initial_policy_set
        self._calculate_policy_tree_intersection(n)

    def _verify_signature(self, cert: x509.Certificate, public_key):
        """
        Verify the signature of the certificate.

        :param cert: The X.509 certificate.
        :param public_key: The public key of the issuer.
        """
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature as e:
            raise PathValidationError(f"Signature verification failed: {e}")
        except Exception as e:
            raise PathValidationError(f"Unexpected error during signature verification: {e}")

    def _check_certificate_validity(self, cert: x509.Certificate, current_time: datetime):
        """
        Check if the certificate is currently valid.

        :param cert: The X.509 certificate.
        :param current_time: The current date and time for validation.
        """
        if not (cert.not_valid_before_utc <= current_time <= cert.not_valid_after_utc):
            raise PathValidationError("Certificate is not currently valid.")

    def _process_policy_mappings(self, policy_mappings_ext, i: int):
        """
        Process the policy mappings extension for the current certificate.

        :param policy_mappings_ext: The PolicyMappings extension object.
        :param i: The index of the current certificate in the chain.
        """
        for mapping in policy_mappings_ext:
            issuer_domain_policy = mapping.issuer_domain_policy.dotted_string
            subject_domain_policy = mapping.subject_domain_policy.dotted_string

            if issuer_domain_policy == "anyPolicy" or subject_domain_policy == "anyPolicy":
                raise PathValidationError("anyPolicy cannot appear in policy mappings.")

            if self.policy_mapping > 0:
                if issuer_domain_policy in self.valid_policy_tree['expected_policy_set']:
                    self.valid_policy_tree['expected_policy_set'] = {subject_domain_policy}
                else:
                    if 'anyPolicy' in self.valid_policy_tree['expected_policy_set']:
                        self.valid_policy_tree['expected_policy_set'] = {subject_domain_policy}
            else:
                if issuer_domain_policy in self.valid_policy_tree['expected_policy_set']:
                    self.valid_policy_tree = None

    def _process_name_constraints(self, name_constraints_ext):
        """
        Process the name constraints extension for the current certificate.

        :param name_constraints_ext: The NameConstraints extension object.
        """
        if name_constraints_ext.permitted_subtrees:
            self.permitted_subtrees = self._intersect_subtrees(self.permitted_subtrees,
                                                               name_constraints_ext.permitted_subtrees)

        if name_constraints_ext.excluded_subtrees:
            self.excluded_subtrees = self._union_subtrees(self.excluded_subtrees,
                                                          name_constraints_ext.excluded_subtrees)

    def _process_policy_constraints(self, policy_constraints_ext):
        """
        Process the policy constraints extension for the current certificate.

        :param policy_constraints_ext: The PolicyConstraints extension object.
        """
        if policy_constraints_ext.require_explicit_policy is not None:
            self.explicit_policy = min(self.explicit_policy, policy_constraints_ext.require_explicit_policy)

        if policy_constraints_ext.inhibit_policy_mapping is not None:
            self.policy_mapping = min(self.policy_mapping, policy_constraints_ext.inhibit_policy_mapping)

    def _process_inhibit_any_policy(self, inhibit_any_policy_ext):
        """
        Process the inhibit anyPolicy extension for the current certificate.

        :param inhibit_any_policy_ext: The InhibitAnyPolicy extension object.
        """
        if inhibit_any_policy_ext is not None:
            self.inhibit_anyPolicy = min(self.inhibit_anyPolicy, inhibit_any_policy_ext)

    def _check_basic_constraints(self, cert: x509.Certificate):
        """
        Verify that the basicConstraints extension is present and that cA is set to TRUE.

        :param cert: The X.509 certificate to check.
        """
        try:
            basic_constraints_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not basic_constraints_ext.ca:
                raise PathValidationError("The certificate is not a CA certificate.")
        except x509.ExtensionNotFound:
            raise PathValidationError("Basic constraints extension is missing.")

    def _process_critical_extensions(self, cert: x509.Certificate):
        """
        Process any other critical extensions in the certificate.

        :param cert: The X.509 certificate to process.
        """
        recognized_critical_extensions = [
            x509.BasicConstraints,
            x509.KeyUsage,
            x509.CertificatePolicies,
            # x509.PolicyMappings
            x509.NameConstraints,
            x509.PolicyConstraints,
            x509.InhibitAnyPolicy,
        ]

        for ext in cert.extensions:
            if ext.critical and type(ext.value) not in recognized_critical_extensions:
                raise PathValidationError(f"Unrecognized critical extension: {ext.oid}")

    def _check_name_constraints(self, cert, subtrees, permitted):
        """
        Check the certificate name constraints against permitted or excluded subtrees.

        :param cert: The X.509 certificate.
        :param subtrees: The set of subtrees to check against.
        :param permitted: Boolean indicating if this is a check for permitted subtrees (True) or excluded subtrees (False).
        """
        if subtrees is None:
            return

        for name in cert.subject.rdns:
            for attr in name:
                if permitted and attr.value not in subtrees:
                    raise PathValidationError("Subject name is not within the permitted subtrees.")
                if not permitted and attr.value in subtrees:
                    raise PathValidationError("Subject name is within the excluded subtrees.")

    def _calculate_policy_tree_intersection(self, n: int):
        """
        Calculate the intersection of the valid_policy_tree and user_initial_policy_set.

        :param n: The depth of the valid_policy_tree (number of certificates).
        """
        if self.valid_policy_tree is None:
            return

        if "any-policy" in self.user_initial_policy_set:
            return

        valid_policy_node_set = set()

        # 1. Determine the set of policy nodes whose parent nodes have a valid_policy of anyPolicy.
        # TODO: Only single level of the policy tree assumed
        if self.valid_policy_tree['valid_policy'] == 'anyPolicy':
            valid_policy_node_set = self.valid_policy_tree['expected_policy_set']

        # 2. Delete nodes not in user_initial_policy_set
        valid_policy_node_set = {p for p in valid_policy_node_set if p in self.user_initial_policy_set}

        if not valid_policy_node_set:
            self.valid_policy_tree = None
            return

        # 3. Handle anyPolicy at depth n
        if self.valid_policy_tree['valid_policy'] == 'anyPolicy':
            p_q = self.valid_policy_tree['qualifier_set']
            for p_oid in self.user_initial_policy_set:
                if p_oid not in valid_policy_node_set:
                    valid_policy_node_set.add(p_oid)
            self.valid_policy_tree['expected_policy_set'] = valid_policy_node_set
            self.valid_policy_tree['qualifier_set'] = p_q

        # 4. Prune nodes without children
        if not self.valid_policy_tree['expected_policy_set']:
            self.valid_policy_tree = None

    def _process_certificate_policies(self, cert: x509.Certificate, i: int, n: int):
        """
        Process the certificate policies for the i-th certificate in the certification path.

        :param cert: The X.509 certificate.
        :param i: The index of the certificate in the chain.
        :param n: The total number of certificates in the chain.
        """
        try:
            # Get the certificate policies extension
            policies_ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value

            if self.valid_policy_tree is None:
                return

            for policy_info in policies_ext:
                policy_oid = policy_info.policy_identifier.dotted_string
                qualifier_set = [qualifier for qualifier in
                                 policy_info.policy_qualifiers] if policy_info.policy_qualifiers is not None else []

                self._update_valid_policy_tree(policy_oid, qualifier_set, i)

            self._prune_valid_policy_tree(i)

        except x509.ExtensionNotFound:
            self.valid_policy_tree = None

    def _update_valid_policy_tree(self, policy_oid: str, qualifier_set: List[str], i: int):
        """
        Update the valid policy tree with the policy OID from the current certificate.

        :param policy_oid: The policy OID.
        :param qualifier_set: The set of policy qualifiers.
        :param i: The index of the certificate in the chain.
        """
        if policy_oid in self.valid_policy_tree['expected_policy_set']:
            # Case where the policy matches one in the expected set
            self.valid_policy_tree['valid_policy'] = policy_oid
            self.valid_policy_tree['qualifier_set'] = qualifier_set
            self.valid_policy_tree['expected_policy_set'] = {policy_oid}

        elif 'anyPolicy' in self.valid_policy_tree['expected_policy_set']:
            # Case where anyPolicy is in the expected set and no exact match
            self.valid_policy_tree['valid_policy'] = policy_oid
            self.valid_policy_tree['qualifier_set'] = qualifier_set
            self.valid_policy_tree['expected_policy_set'] = {policy_oid}

    def _prune_valid_policy_tree(self, i):
        """
        Prune the valid policy tree by removing nodes without child nodes.

        :param i: The index of the certificate in the chain.
        """
        if not self.valid_policy_tree['expected_policy_set']:
            self.valid_policy_tree = None

    def _intersect_subtrees(self, original, new):
        """
        Intersect two sets of subtrees.

        :param original: The original subtrees.
        :param new: The new subtrees to intersect with.
        :return: The intersected set of subtrees.
        """
        # TODO: Implement the logic to perform intersection of subtree lists
        # TODO: simplified placeholder for illustration purposes
        return {key: list(set(original.get(key, [])) & set(new.get(key, []))) for key in set(original) | set(new)}

    def _union_subtrees(self, original, new):
        """
        Union two sets of subtrees.

        :param original: The original subtrees.
        :param new: The new subtrees to union with.
        :return: The unioned set of subtrees.
        """
        # TODO:  Implement the logic to perform union of subtree lists
        # TODO: This is a simplified placeholder for illustration purposes
        return {key: list(set(original.get(key, [])) | set(new.get(key, []))) for key in set(original) | set(new)}

    def _outputs(self) -> Tuple[bool, Optional[Dict]]:
        """
        Return the final outputs after path processing.

        :return: A tuple indicating success and the final state of relevant variables.
        """
        if self.explicit_policy is not None and self.explicit_policy > 0:
            return True, {
                'valid_policy_tree': self.valid_policy_tree,
                'working_public_key': self.working_public_key,
                'working_public_key_algorithm': self.working_public_key_algorithm,
                'working_public_key_parameters': self.working_public_key_parameters
            }

        if self.valid_policy_tree is not None:
            return True, {
                'valid_policy_tree': self.valid_policy_tree,
                'working_public_key': self.working_public_key,
                'working_public_key_algorithm': self.working_public_key_algorithm,
                'working_public_key_parameters': self.working_public_key_parameters
            }

        return False, None

