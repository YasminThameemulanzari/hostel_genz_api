# Architecture Overview

## Three-Layer Architecture

The Hostel Management System follows a clean, three-layer architecture pattern:

1. **Controllers Layer**: Handles HTTP requests and responses
2. **Services Layer**: Contains business logic
3. **Repositories Layer**: Manages data access and database operations

This architecture provides clear separation of concerns, improved testability, and better code organization.

## Architectural Diagram

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│   Controllers   │────▶│    Services     │────▶│  Repositories   │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                               │
        │                                               │
        │                                               ▼
┌─────────────────┐                           ┌─────────────────┐
│                 │                           │                 │
│  HTTP Requests  │                           │    Database     │
│                 │                           │                 │
└─────────────────┘                           └─────────────────┘
```

## Data Flow

1. **Client Request**: The client sends an HTTP request to a specific endpoint.
2. **Controller**: The controller receives the request, validates inputs, and calls the appropriate service method.
3. **Service**: The service applies business logic, calls repository methods, and transforms data.
4. **Repository**: The repository executes database operations and returns data to the service.
5. **Response**: The service returns processed data to the controller, which formats and sends the response to the client.

## Key Components

### Controllers

Controllers handle HTTP requests and responses. They:
- Parse request parameters
- Call appropriate service methods
- Format and send responses
- Handle request-specific error handling

### Services

Services contain the business logic of the application. They:
- Implement domain-specific operations
- Orchestrate data access through repositories
- Perform data validation and business rule enforcement
- Handle service-level error handling

### Repositories

Repositories manage data access and database operations. They:
- Execute SQL queries
- Map database results to domain objects
- Handle database-specific error handling
- Provide a clean API for services to interact with data

## Module Architecture

Each functional module in the system follows the same three-layer architecture:

### Student Management
- **Controllers**: `student.controller.ts`
- **Services**: `student.service.ts`
- **Repositories**: `student.repository.ts`

### Accommodation Management
- **Controllers**: `hostel.controller.ts`, `block.controller.ts`, `room.controller.ts`
- **Services**: `hostel.service.ts`, `block.service.ts`, `room.service.ts`
- **Repositories**: `hostel.repository.ts`, `block.repository.ts`, `room.repository.ts`

### Fee Management
- **Controllers**: `fee.controller.ts`
- **Services**: `fee.service.ts`
- **Repositories**: `fee.repository.ts`

### Mess Management
- **Controllers**: `mess.controller.ts`, `mess-menu.controller.ts`, `mess-subscription.controller.ts`
- **Services**: `mess.service.ts`, `mess-menu.service.ts`, `mess-subscription.service.ts`
- **Repositories**: `mess.repository.ts`, `mess-menu.repository.ts`, `mess-subscription.repository.ts`

### Complaint Management
- **Controllers**: `complaint.controller.ts`
- **Services**: `complaint.service.ts`
- **Repositories**: `complaint.repository.ts`

### Inventory Management
- **Controllers**: `inventory.controller.ts`
- **Services**: `inventory.service.ts`
- **Repositories**: `inventory.repository.ts`

### Reporting
- **Controllers**: `report.controller.ts`
- **Services**: `report.service.ts`
- **Repositories**: `report.repository.ts`

## Benefits of the Architecture

1. **Separation of Concerns**: Each layer has a specific responsibility, making the code more maintainable.
2. **Testability**: Each layer can be tested independently, making unit testing easier.
3. **Code Reusability**: Repository methods can be reused across different services.
4. **Scalability**: The architecture supports scaling by allowing different components to be deployed separately.
5. **Maintainability**: Clear boundaries between layers make it easier to understand and modify the codebase.
6. **Consistency**: All modules follow the same architectural pattern, making the codebase more predictable.
