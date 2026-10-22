"""AgentAuth: self-certifying, rotatable identities for autonomous AI agents."""

__version__ = "0.4.0"

from .audit import AuditLog
from .crypto import KeyPair, Signer
from .grants import AuthorizedAgent, Grant, GrantChain, GrantError, GrantVerifier, trust_principals
from .httpsig import (
    AuthError,
    NonceCache,
    ReplayCache,
    ReplayCacheUnavailable,
    RequestVerifier,
    VerifiedAgent,
    sign_request,
)
from .identity import IdentityState, InvalidEvent, verify_log
from .limits import LimitError, Limits, UsageLedger
from .sdk import (
    AgentIdentity,
    AgentSigAuth,
    RegistryClient,
    RegistryError,
    RegistryKeyResolver,
    RegistryRevocationChecker,
)
from .witness import EquivocationError, KelPins, RegistryPool, SQLitePins

__all__ = [
    "AgentIdentity",
    "AgentSigAuth",
    "AuditLog",
    "AuthError",
    "AuthorizedAgent",
    "EquivocationError",
    "Grant",
    "GrantChain",
    "GrantError",
    "GrantVerifier",
    "IdentityState",
    "InvalidEvent",
    "KelPins",
    "KeyPair",
    "LimitError",
    "Limits",
    "NonceCache",
    "RegistryClient",
    "RegistryError",
    "RegistryKeyResolver",
    "RegistryPool",
    "RegistryRevocationChecker",
    "ReplayCache",
    "ReplayCacheUnavailable",
    "RequestVerifier",
    "SQLitePins",
    "Signer",
    "UsageLedger",
    "VerifiedAgent",
    "sign_request",
    "trust_principals",
    "verify_log",
]
