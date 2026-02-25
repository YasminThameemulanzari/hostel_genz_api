# Hostel Management System

This repository contains a hostel management system API, including database schema and implementation.

## Project Overview

The system manages:
- Student information
- Room allocation
- Mess bills and subscriptions
- Other hostel functions

## Technology Stack

- **Backend**: Node.js with Express and TypeScript
- **Database**: MySQL (without ORM, using mysql2 library)
- **Containerization**: Docker
- **API Documentation**: Swagger/OpenAPI

## Design Documents

1. [Database Schema Design](./database-schema.md)
2. [API Layer Design](./api-design.md)

## Getting Started

### Prerequisites

- Node.js (v16+)
- Docker and Docker Compose
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```

### Database Setup

1. Create a `.env` file based on `.env.example` with your database configuration.
2. Run the database setup script:
   ```
   npm run setup-db
   ```

### Running with Docker

1. Start the services with Docker Compose:
   ```
   docker-compose up -d
   ```

   This will:
   - Start the MySQL database
   - Initialize the database with schema and seed data
   - Start the Node.js application

2. Or run the application locally:
   ```
   npm run dev
   ```

## API Documentation

Once the application is running, you can access the Swagger documentation at:

```
http://localhost:3000/api-docs
```

This provides interactive documentation for all API endpoints.

## API Endpoints

The API includes endpoints for:
- Authentication (login, register)
- Hostel management
- Room allocation
- Mess management and subscriptions
- Complaints
- Fees
- Inventory

## Implementation Status

1. ✅ Database schema implementation
2. ✅ Core API endpoints development
3. ✅ Authentication and authorization
4. ✅ Mess subscription management
5. ✅ API documentation with Swagger
6. ⏳ Advanced features (reporting, analytics)
## Testing with Jest and Supertest

The project uses Jest for unit and integration testing, with Supertest for API endpoint testing.

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test -- --testPathPattern=allocation.controller.basic.test.ts
```

### Test Structure

Tests are organized in the `src/__tests__` directory, mirroring the structure of the source code:

```
src/
├── __tests__/
│   ├── controllers/     # Controller tests
│   ├── services/        # Service tests
│   ├── repositories/    # Repository tests
│   └── utils/           # Utility function tests
```

### Controller Tests

Controller tests use Supertest to make HTTP requests to Express routes and verify responses:

```typescript
// Example controller test
import request from 'supertest';
import express from 'express';
import { getAllAllocations } from '../../controllers/allocation.controller';

// Mock dependencies
jest.mock('../../services/allocation.service');

// Create Express app for testing
const app = express();
app.use(express.json());
app.get('/api/allocations', getAllAllocations);

describe('Allocation Controller', () => {
  it('should return all allocations', async () => {
    const response = await request(app).get('/api/allocations');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('success');
  });
});
```
