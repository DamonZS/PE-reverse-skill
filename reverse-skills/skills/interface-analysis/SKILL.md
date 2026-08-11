---
name: interface-analysis
description: Plan local interface, API descriptor, capture, and endpoint analysis without fetching remote URLs or executing a client.
---

# Interface and Endpoint Analysis

Use this workflow for a supplied OpenAPI document, Postman collection, HAR
capture, local client artifact, or an endpoint URL used only as a descriptor.
The router may parse a URL's scheme, host, and path for classification, but it
never fetches the endpoint.

## Workflow

1. Record the supplied descriptor or local capture in the case scope.
2. Classify the interface as REST, GraphQL, WebSocket, gRPC, or HTTP.
3. Inventory declared routes, methods, schemas, authentication hints, and
   client-side parameters from local material only.
4. Attach `api-security`, `js-reverse`, or `case-review` only when the plan
   identifies a matching local artifact.
5. Write observed and unresolved items into the case evidence record.

## Boundary

- A URL is an input descriptor, not permission to connect.
- Do not replay requests, crawl, fuzz, authenticate, or contact remote hosts.
- Provider and tool execution require an explicit operation outside this plan.

