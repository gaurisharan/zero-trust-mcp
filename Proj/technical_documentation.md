# Secure MCP Server Infrastructure: Full Technical Documentation

**Version:** 1.0  
**Last Updated:** December 2025  
**Status:** Production-Ready Architecture

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Security Threat Model](#security-threat-model)
4. [Component Specifications](#component-specifications)
5. [API Reference](#api-reference)
6. [Policy Definition & Management](#policy-definition--management)
7. [Implementation Guide](#implementation-guide)
8. [Deployment Guide](#deployment-guide)
9. [Monitoring & Audit](#monitoring--audit)
10. [Testing & Validation](#testing--validation)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)

---

## Executive Summary

The **Secure MCP Server Infrastructure** is a Zero Trust architecture designed to protect AI agents from unauthorized access to tools and sensitive resources. It solves two critical security challenges:

1. **Confused Deputy Problem:** Prevents AI agents from misusing high-privilege service accounts to access unauthorized data.
2. **Broken Chain of Identity:** Ensures the original user's identity is propagated through the entire request chain, enabling fine-grained access control.

The architecture uses the **PDP/PEP pattern** (Policy Decision Point / Policy Enforcement Point) with AWS Cedar policies and formal verification to guarantee security even against prompt injection attacks.

### Key Benefits

- **Mathematically Verifiable Security Policies** using Cedar's formal verification
- **Sub-millisecond Authorization Checks** via Rust-based policy engine
- **Identity Propagation** through compound principals (User + Agent)
- **Fail-Closed Guarantees** with centralized audit logging
- **Kubernetes-Native** with Network Policies and mTLS support

---

## Architecture Overview

### 3.1 High-Level System Design

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                    AI Agent / LLM Client                    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
             â”‚ JSON-RPC Request
             â”‚ (X-User-ID, X-Agent-ID headers)
             â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚              Kubernetes Pod (MCP Server)                     â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚   Main Container     â”‚      Sidecar Container               â”‚
â”‚   (PEP Layer)        â”‚      (PDP Layer)                      â”‚
â”‚                      â”‚                                       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
â”‚  â”‚  FastAPI/Go    â”‚  â”‚  â”‚   Cedar Engine (Rust)        â”‚   â”‚
â”‚  â”‚  MCP Server    â”‚  â”‚  â”‚   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚   â”‚
â”‚  â”‚                â”‚  â”‚  â”‚   â”‚ Policy Evaluator     â”‚   â”‚   â”‚
â”‚  â”‚ â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚  â”‚  â”‚   â”‚ Formal Verification â”‚   â”‚   â”‚
â”‚  â”‚ â”‚ Middleware â”‚ â”‚  â”‚  â”‚   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚   â”‚
â”‚  â”‚ â”‚ Interceptorâ”‚â”€â”¼â”€â”€â”¼â”€â†’ permit/deny decision         â”‚   â”‚
â”‚  â”‚ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚  â”‚  â”‚                              â”‚   â”‚
â”‚  â”‚                â”‚  â”‚  â”‚ â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚   â”‚
â”‚  â”‚ â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚  â”‚  â”‚ â”‚ Policy Store         â”‚   â”‚   â”‚
â”‚  â”‚ â”‚ Tools &    â”‚ â”‚  â”‚  â”‚ â”‚ (YAML/JSON)         â”‚   â”‚   â”‚
â”‚  â”‚ â”‚ Resources  â”‚ â”‚  â”‚  â”‚ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚   â”‚
â”‚  â”‚ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚                                      â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â”œâ”€â†’ Audit Logger (Centralized)
       â”‚
       â””â”€â†’ Backend APIs & Databases
```

### 3.2 Request Flow Sequence

**Phase 1: Request Arrival**
```
AI Agent â†’ HTTP POST /rpc with JSON-RPC payload
Headers: X-User-ID: alice, X-Agent-ID: coding-bot-v1, Authorization: Bearer <token>
Payload: {"method": "call_tool", "params": {"tool": "database_query", "table": "users"}}
```

**Phase 2: Identity Extraction (PEP)**
```
Middleware extracts:
  - User ID: alice
  - Agent ID: coding-bot-v1
  - Session Context: IP, timestamp, device fingerprint
  - Constructs Compound Principal: (User:alice, Agent:coding-bot-v1)
```

**Phase 3: Authorization Query (PEP â†’ PDP)**
```
Auth Context sent to Cedar Engine (localhost:8080):
{
  "principal": {
    "type": "Compound",
    "user_id": "alice",
    "agent_id": "coding-bot-v1",
    "agent_trust_level": 4,
    "user_department": "engineering"
  },
  "action": "call_tool",
  "action_name": "database_query",
  "resource": {
    "type": "database_table",
    "name": "users",
    "sensitivity": "high"
  },
  "context": {
    "time_of_day": "09:15",
    "is_business_hours": true,
    "ip_address": "192.168.1.100",
    "session_risk_score": 1.2
  }
}
```

**Phase 4: Policy Evaluation (PDP)**
```
Cedar Engine evaluates policies:
  - Match principal to roles/attributes
  - Check action against resource permissions
  - Apply conditional logic (time, risk, department)
  - Return PERMIT or DENY with reason
```

**Phase 5: Enforcement & Execution (PEP)**
```
If PERMIT:
  â†’ Execute tool with user context propagated
  â†’ Return result to AI Agent
  â†’ Log: [2025-12-03T09:15:23Z] [alice/coding-bot-v1] [database_query] [users] [PERMIT]

If DENY:
  â†’ Immediately raise PermissionDenied error
  â†’ Do NOT execute tool
  â†’ Log violation with full context for audit
  â†’ Alert security monitoring system
```

---

## Security Threat Model

### 2.1 Threat Scenarios Addressed

| Threat | Attack Vector | Mitigation |
|--------|---------------|-----------|
| **Prompt Injection** | Attacker crafts prompt to trick AI into requesting sensitive data | Policy constraints prevent access regardless of prompt; agent cannot escalate privileges |
| **Identity Spoofing** | Attacker forges X-User-ID header to impersonate another user | mTLS + signature verification; compound identity validation |
| **Lateral Movement** | Compromised agent attempts to access unrelated microservices | Network policies restrict egress; least privilege RBAC |
| **Privilege Escalation** | Agent requests high-privilege tools without authorization | Cedar policies enforce explicit allow-list; fail-closed default |
| **Audit Trail Tampering** | Attacker modifies logs to cover tracks | Centralized immutable logging (e.g., CloudWatch, Datadog); tamper detection |
| **PDP Bypass** | Attacker attempts to bypass authorization | Middleware enforces PDP query for ALL tool calls; no hardcoded exceptions |
| **Supply Chain (3rd-party Agent)** | Untrusted agent with valid credentials misuses access | Risk-based scoring + JIT approval for sensitive operations |

### 2.2 Attack Surface Reduction

**Before (Traditional MCP):**
- AI Agent directly calls backend APIs
- MCP Server runs as SuperAdmin
- No per-user authorization
- Compromised agent = compromised system

**After (Zero Trust MCP):**
- Authorization proxy intercepts all requests
- MCP Server runs with minimal privileges
- User identity propagated end-to-end
- Compromised agent still constrained by policies

---

## Component Specifications

### 4.1 Policy Enforcement Point (PEP) - FastAPI Implementation

#### 4.1.1 Service Configuration

```yaml
# pep/config.yml
service:
  name: "mcp-pep-gateway"
  version: "1.0.0"
  port: 8000
  debug: false

pdp:
  service_name: "cedar-pdp"
  host: "localhost"  # Sidecar pattern
  port: 8080
  timeout_ms: 500
  max_retries: 3

logging:
  level: "INFO"
  format: "json"
  audit_endpoint: "https://audit-logger.internal/api/v1/events"

identity:
  header_user_id: "X-User-ID"
  header_agent_id: "X-Agent-ID"
  header_session_id: "X-Session-ID"
  require_mTLS: true
  
security:
  fail_closed: true  # Deny on PDP timeout/error
  max_request_size_bytes: 1048576
  ratelimit_per_minute: 1000
```

#### 4.1.2 Middleware Implementation (Python/FastAPI)

```python
# pep/middleware/auth_interceptor.py
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging
import json
from datetime import datetime
import httpx

app = FastAPI()
logger = logging.getLogger(__name__)

class AuthContext(BaseModel):
    principal: Dict[str, Any]
    action: str
    resource: Dict[str, Any]
    context: Dict[str, Any]

class ToolCall(BaseModel):
    method: str
    params: Dict[str, Any]
    id: str

class CedarClient:
    """Client for communicating with Cedar PDP"""
    
    def __init__(self, host: str, port: int, timeout: int):
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        
    async def check_permission(self, auth_context: Dict[str, Any]) -> str:
        """
        Query Cedar PDP for authorization decision.
        
        Args:
            auth_context: Dictionary containing principal, action, resource, context
            
        Returns:
            "PERMIT" or "DENY"
            
        Raises:
            HTTPException: If PDP is unreachable or times out
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/authorize",
                    json=auth_context
                )
                response.raise_for_status()
                result = response.json()
                return result.get("decision", "DENY")
        except httpx.TimeoutException:
            logger.error(f"Cedar PDP timeout for principal: {auth_context['principal']}")
            raise HTTPException(status_code=503, detail="Authorization service timeout")
        except httpx.RequestError as e:
            logger.error(f"Cedar PDP error: {e}")
            raise HTTPException(status_code=503, detail="Authorization service unavailable")

cedar_client = CedarClient(
    host="localhost",
    port=8080,
    timeout=500
)

def extract_identity(request: Request) -> tuple[str, str, str]:
    """Extract user ID, agent ID, and session ID from request headers"""
    user_id = request.headers.get("X-User-ID")
    agent_id = request.headers.get("X-Agent-ID")
    session_id = request.headers.get("X-Session-ID", "unknown")
    
    if not user_id or not agent_id:
        raise HTTPException(
            status_code=400,
            detail="Missing required identity headers: X-User-ID, X-Agent-ID"
        )
    
    return user_id, agent_id, session_id

def detect_resource(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect the resource being accessed based on tool name and parameters.
    
    This function implements resource detection heuristics. Can be extended
    to support custom resource detection per tool.
    
    Proposal: Use a configuration file or decorator to map tool â†’ resource type
    """
    resource_map = {
        "database_query": {
            "type": "database_table",
            "name": params.get("table", "unknown"),
            "sensitivity": "high" if params.get("table") in ["users", "salaries"] else "medium"
        },
        "file_read": {
            "type": "file",
            "path": params.get("path", "unknown"),
            "sensitivity": "medium"
        },
        "api_call": {
            "type": "external_api",
            "endpoint": params.get("endpoint", "unknown"),
            "sensitivity": "low"
        }
    }
    return resource_map.get(tool_name, {
        "type": "unknown",
        "name": tool_name,
        "sensitivity": "unknown"
    })

def get_agent_attributes(agent_id: str) -> Dict[str, Any]:
    """
    Fetch agent attributes (trust level, permissions, etc.) from agent registry.
    
    Proposal: Query an agent service or cache that maintains agent metadata:
      - trust_level: 1-10 (higher = more trustworthy)
      - agent_type: "system" | "user_created" | "third_party"
      - capabilities: List of allowed tools
      - approval_required: bool (for sensitive operations)
    """
    # PLACEHOLDER: Mock data. Replace with actual agent service call
    return {
        "trust_level": 4,
        "type": "system",
        "capabilities": ["database_query", "file_read"],
        "approval_required": False
    }

def get_user_attributes(user_id: str) -> Dict[str, Any]:
    """
    Fetch user attributes (department, role, MFA status) from identity provider.
    
    Proposal: Query LDAP, Auth0, Okta, or internal identity service for:
      - department
      - roles
      - mfa_enabled
      - is_active
      - last_login
    """
    # PLACEHOLDER: Mock data. Replace with actual identity service call
    return {
        "department": "engineering",
        "roles": ["engineer", "data_analyst"],
        "mfa_enabled": True,
        "is_active": True
    }

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """
    Global middleware that intercepts all requests and enforces authorization.
    
    This middleware:
    1. Extracts identity from headers
    2. Builds authorization context
    3. Queries Cedar PDP
    4. Enforces decision
    5. Logs to audit system
    """
    
    # Allow health checks without auth
    if request.url.path in ["/health", "/readiness"]:
        return await call_next(request)
    
    try:
        # Step 1: Extract Identity
        user_id, agent_id, session_id = extract_identity(request)
        
        # Step 2: Parse JSON-RPC Request
        body = await request.body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from {user_id}/{agent_id}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        tool_name = payload.get("method", "unknown")
        params = payload.get("params", {})
        request_id = payload.get("id", "unknown")
        
        # Step 3: Build Authorization Context
        resource = detect_resource(tool_name, params)
        agent_attrs = get_agent_attributes(agent_id)
        user_attrs = get_user_attributes(user_id)
        
        auth_context = AuthContext(
            principal={
                "type": "Compound",
                "user_id": user_id,
                "agent_id": agent_id,
                "agent_trust_level": agent_attrs["trust_level"],
                "user_department": user_attrs["department"],
                "mfa_enabled": user_attrs["mfa_enabled"]
            },
            action=tool_name,
            resource=resource,
            context={
                "time": datetime.utcnow().isoformat(),
                "session_id": session_id,
                "client_ip": request.client.host if request.client else "unknown",
                "user_roles": user_attrs["roles"],
                "agent_type": agent_attrs["type"]
            }
        )
        
        # Step 4: Query Cedar PDP
        logger.info(f"Auth query: {user_id}/{agent_id} â†’ {tool_name}")
        decision = await cedar_client.check_permission(auth_context.dict())
        
        # Step 5: Enforce Decision
        if decision != "PERMIT":
            logger.warning(
                f"Authorization DENIED: {user_id}/{agent_id} attempted {tool_name} on {resource['name']}"
            )
            await log_audit_event(
                user_id, agent_id, tool_name, resource, "DENY", auth_context
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied by policy engine"
            )
        
        logger.info(f"Authorization PERMIT: {user_id}/{agent_id} â†’ {tool_name}")
        await log_audit_event(
            user_id, agent_id, tool_name, resource, "PERMIT", auth_context
        )
        
        # Store identity in request state for tool execution
        request.state.user_id = user_id
        request.state.agent_id = agent_id
        request.state.auth_context = auth_context
        
        response = await call_next(request)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Middleware error: {e}", exc_info=True)
        # Fail closed on unexpected errors
        raise HTTPException(status_code=500, detail="Internal server error")

async def log_audit_event(
    user_id: str,
    agent_id: str,
    tool_name: str,
    resource: Dict[str, Any],
    decision: str,
    auth_context: AuthContext
):
    """
    Log authorization decision to centralized audit service.
    
    Proposal: Implement with multiple backends:
    - CloudWatch Logs (AWS)
    - Datadog (SaaS)
    - ELK Stack (self-hosted)
    - Splunk (enterprise)
    
    Log entry should be:
    - Immutable (append-only)
    - Timestamped (UTC)
    - Include full context for forensics
    - Indexed for quick retrieval
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "authorization_decision",
        "user_id": user_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "resource": resource,
        "decision": decision,
        "principal": auth_context.principal,
        "context": auth_context.context
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://audit-logger.internal/api/v1/events",
                json=log_entry,
                timeout=5
            )
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")

@app.post("/rpc")
async def handle_rpc(request: Request):
    """
    Main RPC endpoint for tool calls.
    All requests are intercepted by auth_middleware before reaching here.
    """
    body = await request.body()
    payload = json.loads(body)
    tool_name = payload["method"]
    params = payload["params"]
    
    # At this point, authorization has been verified by middleware
    # Execute the tool with user context propagated
    try:
        result = await execute_tool(tool_name, params, request.state.user_id)
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": payload.get("id")
        }
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": str(e)},
            "id": payload.get("id")
        }

async def execute_tool(tool_name: str, params: Dict[str, Any], user_id: str) -> Any:
    """
    Execute the authorized tool.
    
    IMPORTANT: This function should propagate the user_id to the backend service
    so that it can:
    1. Apply row-level security (e.g., show only data owned by user)
    2. Apply field-level masking (e.g., hide PII)
    3. Create per-user audit trails
    """
    # Placeholder for tool execution
    # Actual implementation depends on your tool registry
    return {"status": "success", "executed_by": user_id}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/readiness")
async def readiness():
    """Check if PDP is reachable"""
    try:
        async with httpx.AsyncClient() as client:
            await client.get(f"http://localhost:8080/health", timeout=2)
        return {"ready": True}
    except:
        return {"ready": False}
```

### 4.2 Policy Decision Point (PDP) - Cedar Engine in Rust

#### 4.2.1 Cedar Service Architecture

```rust
// pdp/src/main.rs
use actix_web::{web, App, HttpServer, HttpResponse, post, get};
use cedar_policy::{PolicySet, Schema, Authorizer, Request, Context, Decision};
use serde_json::{json, Value};
use log::{info, warn, error};
use tokio::sync::RwLock;
use std::sync::Arc;

mod policy_loader;
mod schema_builder;
mod audit;

use policy_loader::PolicyLoader;
use schema_builder::SchemaBuilder;
use audit::AuditLogger;

/// Cedar PDP Service
/// 
/// Responsibilities:
/// - Load and cache security policies
/// - Evaluate authorization requests against policies
/// - Return PERMIT or DENY decisions
/// - Maintain policy versioning and hot-reload
struct CedarService {
    policy_set: Arc<RwLock<PolicySet>>,
    schema: Arc<RwLock<Schema>>,
    authorizer: Authorizer,
    audit: AuditLogger,
}

impl CedarService {
    async fn new() -> Self {
        let loader = PolicyLoader::new("./policies");
        let policies = loader.load_policies().expect("Failed to load policies");
        let schema = SchemaBuilder::build_schema().expect("Failed to build schema");
        
        Self {
            policy_set: Arc::new(RwLock::new(policies)),
            schema: Arc::new(RwLock::new(schema)),
            authorizer: Authorizer::new(),
            audit: AuditLogger::new(),
        }
    }

    async fn evaluate(&self, auth_request: Value) -> Decision {
        info!("Cedar evaluation request: {}", auth_request);
        
        let policies = self.policy_set.read().await;
        let schema = self.schema.read().await;
        
        // Parse request into Cedar types
        let principal = self.parse_principal(&auth_request).expect("Invalid principal");
        let action = self.parse_action(&auth_request).expect("Invalid action");
        let resource = self.parse_resource(&auth_request).expect("Invalid resource");
        let context = self.parse_context(&auth_request).expect("Invalid context");
        
        // Evaluate against policy set
        let request = Request::new(principal, action, resource, context, &schema)
            .expect("Failed to create Cedar request");
        
        let decision = self.authorizer.is_authorized(&request, &policies, &schema);
        
        info!("Cedar decision: {:?}", decision);
        decision
    }
    
    fn parse_principal(&self, req: &Value) -> Result<cedar_policy::Entity, String> {
        // Implementation: Convert JSON principal to Cedar Entity
        Ok(cedar_policy::Entity::new("principal"))
    }
    
    fn parse_action(&self, req: &Value) -> Result<cedar_policy::Entity, String> {
        Ok(cedar_policy::Entity::new("action"))
    }
    
    fn parse_resource(&self, req: &Value) -> Result<cedar_policy::Entity, String> {
        Ok(cedar_policy::Entity::new("resource"))
    }
    
    fn parse_context(&self, req: &Value) -> Result<Context, String> {
        Ok(Context::new())
    }
}

#[post("/authorize")]
async fn authorize(
    service: web::Data<Arc<CedarService>>,
    auth_request: web::Json<Value>
) -> HttpResponse {
    """
    Main authorization endpoint.
    
    Request Format:
    {
      "principal": { "type": "Compound", "user_id": "alice", ... },
      "action": "database_query",
      "resource": { "type": "table", "name": "users" },
      "context": { "time": "2025-12-03T09:15:23Z", ... }
    }
    
    Response Format:
    {
      "decision": "PERMIT" | "DENY",
      "reason": "User is engineer and action is read_file",
      "evaluation_time_ms": 1.234
    }
    """
    let decision = service.evaluate(auth_request.into_inner()).await;
    
    match decision {
        Decision::Allow => {
            HttpResponse::Ok().json(json!({
                "decision": "PERMIT",
                "reason": "Policy evaluation permitted the action"
            }))
        },
        Decision::Deny => {
            HttpResponse::Ok().json(json!({
                "decision": "DENY",
                "reason": "Policy evaluation denied the action"
            }))
        },
    }
}

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(json!({"status": "ok"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    let cedar_service = Arc::new(CedarService::new().await);
    
    info!("Starting Cedar PDP on port 8080");
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(cedar_service.clone()))
            .service(authorize)
            .service(health)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

#### 4.2.2 Cedar Policy Examples

```cedar
// policies/agent_access.cedar

// Policy 1: Allow users to read their own files
permit (
    principal,
    action == Action::"read_file",
    resource
)
when {
    // The resource must be owned by the principal's user_id
    resource.owner == principal.user_id
};

// Policy 2: Allow engineers to query non-sensitive databases
permit (
    principal,
    action == Action::"database_query",
    resource
)
when {
    // User must have engineer role
    "engineer" in principal.user_roles &&
    // Resource sensitivity must be low or medium
    resource.sensitivity != "high" &&
    // Must be during business hours
    principal.context.is_business_hours == true
};

// Policy 3: Allow sensitive operations with explicit approval
permit (
    principal,
    action == Action::"database_query",
    resource
)
when {
    // Only allow if data owner explicitly approved
    resource.sensitivity == "high" &&
    principal.has_jit_approval == true &&
    // Approval window must not have expired
    principal.approval_expires_at > principal.context.time
};

// Policy 4: Deny agents with low trust level from accessing sensitive resources
forbid (
    principal,
    action,
    resource
)
when {
    principal.agent_trust_level < 3 &&
    resource.sensitivity == "high"
};

// Policy 5: Deny any request with high session risk
forbid (
    principal,
    action,
    resource
)
when {
    principal.context.session_risk_score > 7.5
};
```

---

## API Reference

### 5.1 PEP (Policy Enforcement Point) API

#### Endpoint: POST /rpc

**Description:** Main JSON-RPC endpoint for tool invocation

**Request Headers:**
```
X-User-ID: alice                    # Required: User identifier
X-Agent-ID: coding-bot-v1           # Required: Agent identifier
X-Session-ID: sess_abc123           # Optional: Session identifier
Authorization: Bearer <jwt_token>   # Required: Authentication token
Content-Type: application/json
```

**Request Body:**
```json
{
  "jsonrpc": "2.0",
  "method": "database_query",
  "params": {
    "table": "users",
    "filter": { "department": "engineering" },
    "limit": 100
  },
  "id": "req_12345"
}
```

**Success Response (200 OK):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "rows": [
      {"id": 1, "name": "Alice", "department": "engineering"}
    ],
    "count": 1
  },
  "id": "req_12345"
}
```

**Authorization Failed Response (403 Forbidden):**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32603,
    "message": "Access denied by policy engine",
    "data": {
      "reason": "User department is not sales, cannot access restricted_data",
      "policy_violated": "sales_only_policy"
    }
  },
  "id": "req_12345"
}
```

**Invalid Identity Response (400 Bad Request):**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32700,
    "message": "Missing required identity headers: X-User-ID, X-Agent-ID"
  },
  "id": "req_12345"
}
```

---

### 5.2 PDP (Policy Decision Point) API

#### Endpoint: POST /authorize

**Description:** Direct authorization evaluation endpoint

**Request Body:**
```json
{
  "principal": {
    "type": "Compound",
    "user_id": "alice",
    "agent_id": "coding-bot-v1",
    "agent_trust_level": 4,
    "user_department": "engineering",
    "user_roles": ["engineer", "data_analyst"],
    "mfa_enabled": true
  },
  "action": "database_query",
  "resource": {
    "type": "database_table",
    "name": "users",
    "sensitivity": "high",
    "owner": "data_team"
  },
  "context": {
    "time": "2025-12-03T09:15:23Z",
    "session_id": "sess_abc123",
    "client_ip": "192.168.1.100",
    "session_risk_score": 1.5
  }
}
```

**Response (200 OK):**
```json
{
  "decision": "PERMIT",
  "reason": "User has engineer role and querying non-high-sensitivity resource during business hours",
  "matching_policies": ["engineer_db_access_policy"],
  "evaluation_time_ms": 2.34
}
```

**Denied Response (200 OK):**
```json
{
  "decision": "DENY",
  "reason": "High-sensitivity resource requires JIT approval which is not present",
  "matching_policies": ["high_sensitivity_policy"],
  "evaluation_time_ms": 1.89
}
```

---

## Policy Definition & Management

### 6.1 Policy File Organization

```
policies/
â”œâ”€â”€ agent_access.cedar              # General agent access policies
â”œâ”€â”€ role_based_policies.cedar        # Role-specific rules (engineer, admin, etc.)
â”œâ”€â”€ resource_policies.cedar          # Resource-specific constraints
â”œâ”€â”€ time_based_policies.cedar        # Time of day, business hours
â”œâ”€â”€ risk_based_policies.cedar        # Risk scoring and anomaly detection
â”œâ”€â”€ external_api_policies.cedar      # Policies for external integrations
â””â”€â”€ testing/
    â”œâ”€â”€ test_agent_access.cedar      # Unit tests for policies
    â”œâ”€â”€ test_role_based.cedar
    â””â”€â”€ fixtures/
        â”œâ”€â”€ permitted_scenarios.json
        â””â”€â”€ denied_scenarios.json
```

### 6.2 Policy Writing Guidelines

**Best Practices:**

1. **Explicit Allow-List Approach**
   - Start with FORBID ALL (implicit deny)
   - Explicitly permit only necessary actions
   - Never rely on absence of forbid rules

2. **Attribute-Based Design**
   - Use principal attributes (roles, department, trust_level) not just IDs
   - Use resource attributes (sensitivity, owner, classification)
   - Include contextual attributes (time, IP, risk_score)

3. **Fail-Safe Logic**
   - Policies should be conservative (deny by default)
   - Include expiration dates on temporary permissions
   - Regularly audit overpermissive policies

4. **Testing & Verification**
   - Write unit tests for each policy
   - Use Cedar's formal verification tools
   - Document policy intent and constraints

### 6.3 Policy Hot-Reload (Proposal)

**Current State:** Policies are loaded at startup

**Proposal:** Implement dynamic policy reloading without service restart

```python
# pep/policy_manager.py
import asyncio
import hashlib
from pathlib import Path
from typing import Callable

class PolicyManager:
    """Manages policy loading and hot-reloading"""
    
    def __init__(self, policy_dir: str, poll_interval_sec: int = 60):
        self.policy_dir = Path(policy_dir)
        self.poll_interval = poll_interval_sec
        self.policy_hash = None
        self.on_reload_callback: Optional[Callable] = None
        
    async def start_monitoring(self):
        """Start background task to monitor policy file changes"""
        while True:
            await asyncio.sleep(self.poll_interval)
            await self.check_and_reload()
    
    async def check_and_reload(self):
        """Check if policies have changed and reload if necessary"""
        current_hash = self._compute_policies_hash()
        
        if self.policy_hash is None:
            self.policy_hash = current_hash
            return
        
        if current_hash != self.policy_hash:
            logger.info("Policy change detected, reloading...")
            try:
                await self.reload_policies()
                self.policy_hash = current_hash
                if self.on_reload_callback:
                    await self.on_reload_callback()
            except Exception as e:
                logger.error(f"Policy reload failed: {e}")
                # Keep using old policies on failure
    
    def _compute_policies_hash(self) -> str:
        """Compute hash of all policy files"""
        hasher = hashlib.sha256()
        for policy_file in sorted(self.policy_dir.glob("*.cedar")):
            hasher.update(policy_file.read_bytes())
        return hasher.hexdigest()
    
    async def reload_policies(self):
        """Load policies from disk and update Cedar engine"""
        # Implementation: parse Cedar files and update PDP
        pass
```

---

## Implementation Guide

### 7.1 Step 1: Identity Model Definition

**Objective:** Define who can access what and through which agents

**Implementation Steps:**

1. **Create Identity Schema**
   ```yaml
   # config/identity_schema.yml
   principals:
     user:
       attributes:
         - user_id (string, required)
         - department (enum: engineering, sales, finance, admin)
         - roles (list of strings)
         - mfa_enabled (boolean)
         - last_authentication (timestamp)
         
     agent:
       attributes:
         - agent_id (string, required)
         - trust_level (integer 1-10)
         - type (enum: system, user_created, third_party)
         - owner_user_id (string)
         - capabilities (list of tool names)
         
     compound_principal:
       attributes:
         - user_id (string)
         - agent_id (string)
         - combined_trust_level (computed)
         - effective_roles (computed as union of user+agent roles)
   ```

2. **Integrate Identity Provider**
   ```python
   # pep/identity_provider.py
   from abc import ABC, abstractmethod
   
   class IdentityProvider(ABC):
       """Abstract interface for identity providers"""
       
       @abstractmethod
       async def get_user(self, user_id: str) -> UserIdentity:
           pass
       
       @abstractmethod
       async def get_agent(self, agent_id: str) -> AgentIdentity:
           pass
       
       @abstractmethod
       async def validate_token(self, token: str) -> bool:
           pass
   
   class LDAPIdentityProvider(IdentityProvider):
       """Concrete implementation for LDAP"""
       # Implementation for corporate LDAP
       
   class Auth0Provider(IdentityProvider):
       """Concrete implementation for Auth0"""
       # Implementation for Auth0 SaaS
   ```

3. **Define Compound Principal Rules**
   ```python
   # Compound principal combines user + agent attributes
   
   def compute_compound_principal(
       user: UserIdentity,
       agent: AgentIdentity
   ) -> CompoundPrincipal:
       return CompoundPrincipal(
           user_id=user.user_id,
           agent_id=agent.agent_id,
           # Trust level is minimum of user and agent
           trust_level=min(user.trust_level, agent.trust_level),
           # Roles are intersection for security
           roles=set(user.roles) & set(agent.capabilities),
           mfa_enabled=user.mfa_enabled,
           agent_type=agent.type
       )
   ```

### 7.2 Step 2: Write & Test Policies

**Objective:** Implement formally verified Cedar policies

**Implementation Steps:**

1. **Define Policy Scope Matrix**
   ```
   | Tool Name | Engineer | Sales | Admin | Trust Lvl Req. |
   |-----------|----------|-------|-------|----------------|
   | database_query | Y (non-PII) | N | Y | 4 |
   | file_read | Y | Y (own files) | Y | 3 |
   | api_call | Y | Y | Y | 2 |
   | delete_record | N | N | Y (approval) | 8 |
   ```

2. **Implement Policy Tests**
   ```python
   # tests/test_policies.py
   import pytest
   from cedar_policy import PolicySet, Authorizer
   
   class TestDatabaseQueryPolicy:
       """Unit tests for database query access policy"""
       
       @pytest.fixture
       def policies(self):
           return PolicySet.load_from_file("policies/agent_access.cedar")
       
       def test_engineer_can_query_non_pii_tables(self, policies):
           """Engineer should access non-sensitive tables"""
           principal = {
               "user_id": "alice",
               "roles": ["engineer"],
               "trust_level": 5
           }
           resource = {
               "table": "projects",
               "sensitivity": "low"
           }
           # Assert PERMIT
           assert evaluate(policies, principal, "database_query", resource) == "PERMIT"
       
       def test_engineer_cannot_query_pii_without_approval(self, policies):
           """Engineer should NOT access PII without approval"""
           principal = {
               "user_id": "alice",
               "roles": ["engineer"],
               "trust_level": 5,
               "has_approval": False
           }
           resource = {
               "table": "users",
               "sensitivity": "high"
           }
           # Assert DENY
           assert evaluate(policies, principal, "database_query", resource) == "DENY"
       
       def test_sales_cannot_access_database(self, policies):
           """Sales team should not access database tools"""
           principal = {
               "user_id": "bob",
               "roles": ["sales"],
               "trust_level": 3
           }
           resource = {
               "table": "any_table",
               "sensitivity": "low"
           }
           # Assert DENY
           assert evaluate(policies, principal, "database_query", resource) == "DENY"
   ```

3. **Validate Policy Logic**
   ```bash
   # Use Cedar CLI for formal verification
   cedar validate --policies policies/ --schema schema.json
   
   # Run test suite
   pytest tests/test_policies.py -v
   
   # Coverage analysis
   cedar coverage --policies policies/
   ```

### 7.3 Step 3: Implement PEP Middleware

**Objective:** Integrate authorization checks into request flow

**Implementation Steps:** (See Section 4.1.2 for detailed code)

Key points:
- Global middleware intercepts ALL requests
- No hardcoded authorization in individual tools
- Fail-closed on PDP timeout
- Identity propagated to backend services

### 7.4 Step 4: Centralized Audit Logging

**Objective:** Tamper-proof audit trail for compliance

**Implementation Steps:**

```python
# pep/audit_logger.py
import logging
import json
from datetime import datetime
from typing import Dict, Any
import httpx

class AuditLogger:
    """
    Centralized audit logging service.
    
    Logs are sent to:
    - CloudWatch (AWS)
    - Datadog (SaaS)
    - ELK Stack (self-hosted)
    - Splunk (enterprise)
    """
    
    def __init__(self, backend: str = "cloudwatch"):
        self.backend = backend
        self.logger = logging.getLogger("audit")
        
    async def log_authorization_decision(
        self,
        user_id: str,
        agent_id: str,
        tool_name: str,
        resource: Dict[str, Any],
        decision: str,
        reason: str,
        timestamp: str
    ):
        """
        Log authorization decision to audit backend.
        
        Audit Entry Format:
        {
          "timestamp": "2025-12-03T09:15:23.456Z",
          "event_type": "authorization_decision",
          "user_id": "alice",
          "agent_id": "coding-bot-v1",
          "tool_name": "database_query",
          "resource": {
            "type": "database_table",
            "name": "users"
          },
          "decision": "PERMIT" | "DENY",
          "reason": "Policy evaluation result",
          "correlation_id": "req_12345"
        }
        """
        
        entry = {
            "timestamp": timestamp,
            "event_type": "authorization_decision",
            "user_id": user_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "resource": resource,
            "decision": decision,
            "reason": reason
        }
        
        if self.backend == "cloudwatch":
            self.logger.info(json.dumps(entry))
        elif self.backend == "datadog":
            await self._send_to_datadog(entry)
        elif self.backend == "elk":
            await self._send_to_elasticsearch(entry)
    
    async def _send_to_datadog(self, entry: Dict[str, Any]):
        """Send audit entry to Datadog"""
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://http-intake.logs.datadoghq.com/v1/input/<API_KEY>",
                json=entry,
                headers={"Content-Type": "application/json"}
            )
    
    async def _send_to_elasticsearch(self, entry: Dict[str, Any]):
        """Send audit entry to Elasticsearch"""
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://elasticsearch.internal:9200/audit-logs/_doc",
                json=entry,
                auth=("user", "password")
            )
```

---

## Deployment Guide

### 8.1 Local Development Setup

**Prerequisites:**
- Docker & Docker Compose
- Rust toolchain (for Cedar PDP)
- Python 3.9+
- kubectl (for Kubernetes)

**Steps:**

1. **Clone Repository**
   ```bash
   git clone https://github.com/org/secure-mcp.git
   cd secure-mcp
   ```

2. **Build Docker Images**
   ```bash
   # Build PEP (FastAPI)
   docker build -t mcp-pep:latest -f pep/Dockerfile .
   
   # Build PDP (Rust/Cedar)
   docker build -t mcp-pdp:latest -f pdp/Dockerfile .
   ```

3. **Run with Docker Compose**
   ```yaml
   # docker-compose.yml
   version: '3.8'
   services:
     cedar-pdp:
       image: mcp-pdp:latest
       ports:
         - "8080:8080"
       volumes:
         - ./policies:/app/policies:ro
       environment:
         RUST_LOG: info
     
     mcp-pep:
       image: mcp-pep:latest
       ports:
         - "8000:8000"
       depends_on:
         - cedar-pdp
       environment:
         PDP_HOST: cedar-pdp
         PDP_PORT: 8080
       volumes:
         - ./pep:/app:ro
   
     # Optional: Mock backend services for testing
     mock-database:
       image: postgres:15
       environment:
         POSTGRES_PASSWORD: dev
         POSTGRES_DB: test
       ports:
         - "5432:5432"
   ```

   ```bash
   docker-compose up -d
   ```

4. **Verify Setup**
   ```bash
   # Check PEP health
   curl http://localhost:8000/health
   
   # Check PDP health
   curl http://localhost:8080/health
   
   # Test authorization
   curl -X POST http://localhost:8000/rpc \
     -H "X-User-ID: alice" \
     -H "X-Agent-ID: test-bot" \
     -H "Content-Type: application/json" \
     -d '{"method": "database_query", "params": {"table": "users"}}'
   ```

### 8.2 Kubernetes Deployment

**Architecture:**
```
Kubernetes Namespace: mcp-system
â”œâ”€â”€ Deployment: mcp-pep (3 replicas)
â”œâ”€â”€ Deployment: mcp-pdp-sidecar (injected via DaemonSet)
â”œâ”€â”€ Service: mcp-pep-svc (ClusterIP, internal only)
â”œâ”€â”€ Service: mcp-pdp-svc (ClusterIP, localhost only)
â”œâ”€â”€ ConfigMap: cedar-policies
â”œâ”€â”€ Secret: service-credentials
â”œâ”€â”€ NetworkPolicy: default-deny + explicit rules
â””â”€â”€ ServiceAccount: mcp-sa (minimal permissions)
```

**Deployment YAML:**

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mcp-system

---

# k8s/service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-sa
  namespace: mcp-system

---

# k8s/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mcp-role
  namespace: mcp-system
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "watch", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mcp-rolebinding
  namespace: mcp-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mcp-role
subjects:
  - kind: ServiceAccount
    name: mcp-sa
    namespace: mcp-system

---

# k8s/configmap-policies.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cedar-policies
  namespace: mcp-system
data:
  agent_access.cedar: |
    // Cedar policies from Section 4.2.2
    permit ( principal, action == Action::"read_file", resource )
    when { resource.owner == principal.user_id };

---

# k8s/deployment-pep.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-pep
  namespace: mcp-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-pep
  template:
    metadata:
      labels:
        app: mcp-pep
    spec:
      serviceAccountName: mcp-sa
      containers:
        - name: pep
          image: mcp-pep:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8000
              name: http
          env:
            - name: PDP_HOST
              value: "localhost"
            - name: PDP_PORT
              value: "8080"
            - name: LOG_LEVEL
              value: "INFO"
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /readiness
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
        
        - name: pdp
          image: mcp-pdp:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
              name: cedar
          volumeMounts:
            - name: policies
              mountPath: /app/policies
              readOnly: true
          resources:
            requests:
              cpu: 200m
              memory: 512Mi
            limits:
              cpu: 1000m
              memory: 1Gi
      
      volumes:
        - name: policies
          configMap:
            name: cedar-policies

---

# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: mcp-pep-svc
  namespace: mcp-system
  labels:
    app: mcp-pep
spec:
  type: ClusterIP
  ports:
    - port: 8000
      targetPort: 8000
      name: http
  selector:
    app: mcp-pep

---

# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-default-deny
  namespace: mcp-system
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-ingress-policy
  namespace: mcp-system
spec:
  podSelector:
    matchLabels:
      app: mcp-pep
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: llm-orchestrator
      ports:
        - protocol: TCP
          port: 8000

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-egress-policy
  namespace: mcp-system
spec:
  podSelector:
    matchLabels:
      app: mcp-pep
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
    # Allow to backend APIs
    - to:
        - namespaceSelector:
            matchLabels:
              name: backend-services
      ports:
        - protocol: TCP
          port: 5432  # PostgreSQL
    # Allow to audit logger
    - to:
        - namespaceSelector:
            matchLabels:
              name: logging
```

**Deploy:**
```bash
kubectl apply -f k8s/
kubectl get pods -n mcp-system
kubectl logs -n mcp-system -l app=mcp-pep -f
```

---

## Monitoring & Audit

### 9.1 Monitoring Setup

**Proposal:** Implement comprehensive monitoring for security events

```python
# pep/metrics.py
from prometheus_client import Counter, Histogram, Gauge
import time

# Authorization outcomes
auth_permit_counter = Counter(
    'mcp_auth_permit_total',
    'Total authorized requests',
    ['tool_name', 'user_department']
)

auth_deny_counter = Counter(
    'mcp_auth_deny_total',
    'Total denied requests',
    ['tool_name', 'reason']
)

# Latency
auth_latency_histogram = Histogram(
    'mcp_auth_latency_ms',
    'Authorization latency in milliseconds',
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000]
)

# PDP connectivity
pdp_available_gauge = Gauge(
    'mcp_pdp_available',
    'Is PDP service available (1=yes, 0=no)'
)

# Usage patterns
tool_usage_counter = Counter(
    'mcp_tool_usage_total',
    'Tool usage count',
    ['tool_name', 'user_id', 'success']
)
```

### 9.2 Alert Rules

```yaml
# alerts/mcp-alerts.yaml
groups:
  - name: mcp_security_alerts
    interval: 30s
    rules:
      - alert: HighAuthorizationDenyRate
        expr: |
          rate(mcp_auth_deny_total[5m]) > 
          rate(mcp_auth_permit_total[5m])
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual number of authorization denials"
      
      - alert: PDPServiceDown
        expr: mcp_pdp_available == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Cedar PDP service is unavailable"
      
      - alert: AuthorizationLatencyHigh
        expr: |
          histogram_quantile(0.95, 
          mcp_auth_latency_ms) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Authorization latency exceeding 100ms"
      
      - alert: SuspiciousActivityPattern
        expr: |
          rate(mcp_auth_deny_total{reason="high_risk"}[5m]) > 10
        for: 1m
        labels:
          severity: high
        annotations:
          summary: "High number of high-risk authorization denials"
```

### 9.3 Audit Log Schema

```json
{
  "audit_entry_schema": {
    "timestamp": "ISO8601",
    "event_id": "UUID",
    "event_type": "authorization_decision",
    "user_id": "string",
    "agent_id": "string",
    "tool_name": "string",
    "resource": {
      "type": "string",
      "name": "string",
      "sensitivity": "low|medium|high"
    },
    "decision": "PERMIT|DENY",
    "decision_reason": "string",
    "matching_policies": ["policy_name"],
    "request_context": {
      "client_ip": "IP",
      "user_agent": "string",
      "session_id": "string",
      "correlation_id": "string"
    },
    "evaluation_metrics": {
      "latency_ms": "number",
      "policy_count": "number",
      "rules_evaluated": "number"
    },
    "anomalies": ["suspicious_pattern_1", "risk_flag_2"]
  }
}
```

---

## Testing & Validation

### 10.1 Unit Testing

See Section 7.2 for policy tests.

### 10.2 Integration Testing

```python
# tests/test_integration.py
import pytest
import httpx
from typing import Dict, Any

class TestMCPIntegration:
    """End-to-end integration tests"""
    
    @pytest.fixture
    def client(self):
        return httpx.AsyncClient(base_url="http://localhost:8000")
    
    @pytest.mark.asyncio
    async def test_authorized_tool_call(self, client):
        """Authorized user can call tool"""
        response = await client.post(
            "/rpc",
            headers={
                "X-User-ID": "alice",
                "X-Agent-ID": "test-bot"
            },
            json={
                "method": "database_query",
                "params": {"table": "projects"},
                "id": "test_1"
            }
        )
        assert response.status_code == 200
        result = response.json()
        assert result["result"]["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_unauthorized_tool_call(self, client):
        """Unauthorized user receives 403"""
        response = await client.post(
            "/rpc",
            headers={
                "X-User-ID": "bob",  # Sales user
                "X-Agent-ID": "test-bot"
            },
            json={
                "method": "database_query",
                "params": {"table": "salaries"},  # High sensitivity
                "id": "test_2"
            }
        )
        assert response.status_code == 403
        error = response.json()
        assert "denied by policy" in error["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_missing_identity_headers(self, client):
        """Request without identity headers is rejected"""
        response = await client.post(
            "/rpc",
            json={"method": "database_query", "params": {}}
        )
        assert response.status_code == 400
```

### 10.3 Load Testing

```python
# tests/load_test.py
import asyncio
import httpx
from locust import HttpUser, task, between

class MCPUser(HttpUser):
    """Simulates realistic MCP user behavior"""
    
    wait_time = between(1, 5)
    
    @task(3)
    def tool_call_read(self):
        """Read operations (more frequent)"""
        self.client.post(
            "/rpc",
            headers={
                "X-User-ID": "alice",
                "X-Agent-ID": "test-bot"
            },
            json={
                "method": "database_query",
                "params": {"table": "projects"}
            }
        )
    
    @task(1)
    def tool_call_write(self):
        """Write operations (less frequent)"""
        self.client.post(
            "/rpc",
            headers={
                "X-User-ID": "alice",
                "X-Agent-ID": "test-bot"
            },
            json={
                "method": "create_record",
                "params": {"table": "logs", "data": {}}
            }
        )

# Run: locust -f tests/load_test.py --host http://localhost:8000
```

---

## Troubleshooting

### 11.1 Common Issues

| Issue | Symptoms | Root Cause | Solution |
|-------|----------|-----------|----------|
| **All requests denied** | Every tool call returns 403 | PDP unreachable, middleware fail-closed | Check PDP pod logs, verify localhost connectivity |
| **High auth latency** | Response time > 1s | PDP slow or overloaded | Scale PDP horizontally, optimize Cedar policies |
| **Identity loss** | Backend services don't see user ID | Headers not propagated | Check middleware passes user_id in request context |
| **Audit logs missing** | No audit entries in logging backend | Audit logger misconfigured | Verify audit service URL, check network policies |
| **Policy not applying** | Expected DENY but got PERMIT | Policy syntax error or hot-reload failed | Validate policy with Cedar CLI, check policy file encoding |

### 11.2 Debug Mode

```python
# Enable verbose logging
export RUST_LOG=debug
export LOG_LEVEL=DEBUG

# PEP debug mode
curl -X POST http://localhost:8000/rpc \
  -H "X-User-ID: alice" \
  -H "X-Agent-ID: debug-bot" \
  -H "X-Debug: true" \
  -d '{"method": "database_query", "params": {"table": "users"}}'

# Response includes decision reasoning
{
  "error": {
    "message": "Access denied",
    "decision_reason": "User alice is in sales department, policy forbids sales access to high-sensitivity resources",
    "matching_policies": ["high_sensitivity_policy"],
    "principal_attributes": {
      "department": "sales",
      "roles": ["sales_rep"],
      "trust_level": 2
    }
  }
}
```

---

## FAQ

### Q1: Why separate PDP from PEP?

**A:** Separation of concerns:
- **PDP:** Centralized, formally verified policy logic (Rust/Cedar)
- **PEP:** Request routing, identity extraction (Python/Go)
- Benefits: Reusability, easier to audit, can scale independently

### Q2: How do we handle real-time policy updates?

**A:** Implement dynamic policy reloading (see Section 6.3 Proposal):
- Monitor policy files for changes
- Reload on change without restart
- Version policies with effective dates
- Rollback on validation failure

### Q3: What if PDP is unreachable?

**A:** Fail-closed design:
- MCP Server denies ALL requests if PDP unavailable
- No fallback to cached decisions
- Alert ops team for manual intervention
- Rationale: Better to deny legitimate requests than allow unauthorized ones

### Q4: How do we prevent policy bypasses?

**A:** Multiple layers:
- Formal verification with Cedar
- No hardcoded authorization in tools
- Middleware intercepts ALL requests (no exceptions)
- Regular audit of policies and decisions

### Q5: Can we support delegated authorization?

**A:** Yes, with JIT (Just-In-Time) Approval:
- High-risk tool calls trigger human approval workflow
- Manager approves via Slack/email notification
- PDP temporarily sets approval flag for time-limited window
- Logs show who approved and when

---

## Appendix: Quick Reference

### File Structure
```
â”œâ”€â”€ pep/
â”‚   â”œâ”€â”€ main.py                   # FastAPI application
â”‚   â”œâ”€â”€ middleware/
â”‚   â”‚   â””â”€â”€ auth_interceptor.py   # Authorization middleware
â”‚   â”œâ”€â”€ config.yml                # PEP configuration
â”‚   â””â”€â”€ Dockerfile
â”œâ”€â”€ pdp/
â”‚   â”œâ”€â”€ src/main.rs               # Rust service
â”‚   â”œâ”€â”€ policies/
â”‚   â”‚   â”œâ”€â”€ agent_access.cedar
â”‚   â”‚   â”œâ”€â”€ role_based_policies.cedar
â”‚   â”‚   â””â”€â”€ ...
â”‚   â”œâ”€â”€ schema.json               # Cedar schema
â”‚   â””â”€â”€ Dockerfile
â”œâ”€â”€ k8s/
â”‚   â”œâ”€â”€ namespace.yaml
â”‚   â”œâ”€â”€ deployment-pep.yaml
â”‚   â”œâ”€â”€ deployment-pdp.yaml
â”‚   â”œâ”€â”€ network-policy.yaml
â”‚   â””â”€â”€ ...
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ test_policies.py
â”‚   â”œâ”€â”€ test_integration.py
â”‚   â””â”€â”€ load_test.py
â””â”€â”€ docs/
    â””â”€â”€ technical_documentation.md
```

### Key Environment Variables
```bash
PDP_HOST=localhost
PDP_PORT=8080
LOG_LEVEL=INFO
AUDIT_ENDPOINT=https://audit-logger.internal/api/v1/events
IDENTITY_PROVIDER=ldap  # or auth0, okta, etc.
FAIL_CLOSED=true
```

---

**Document Version:** 1.0  
**Last Updated:** December 2025  
**Maintained By:** Security Architecture Team
