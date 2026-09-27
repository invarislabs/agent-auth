"""AgentAuth: self-certifying, rotatable identities for autonomous AI agents."""

from .crypto import KeyPair
from .grants import AuthorizedAgent, Grant, GrantChain, GrantError, GrantVerifier, trust_principals
from .httpsig import AuthError, NonceCache, RequestVerifier, VerifiedAgent, sign_request
from .limits import LimitError, Limits, UsageLedger
from .identity import IdentityState, InvalidEvent, verify_log
from .sdk import (
    AgentIdentity,
    AgentSigAuth,
    RegistryClient,
    RegistryError,
    RegistryKeyResolver,
    RegistryRevocationChecker,
)

__all__ = [
    "AgentIdentity",
    "AgentSigAuth",
    "AuthError",
    "AuthorizedAgent",
    "Grant",
    "GrantChain",
    "GrantError",
    "GrantVerifier",
    "RegistryRevocationChecker",
    "trust_principals",
    "IdentityState",
    "InvalidEvent",
    "KeyPair",
    "LimitError",
    "Limits",
    "UsageLedger",
    "NonceCache",
    "RegistryClient",
    "RegistryError",
    "RegistryKeyResolver",
    "RequestVerifier",
    "VerifiedAgent",
    "sign_request",
    "verify_log",
]
__version__ = "0.3.0"
