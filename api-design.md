# Hostel Management System - API Layer Design

This document outlines the RESTful API design for the Hostel Management System using Node.js, Express, TypeScript, and MySQL.

## Table of Contents

1. [Project Structure](#project-structure)
2. [Core Components](#core-components)
3. [Authentication & Authorization](#authentication--authorization)
4. [API Endpoints](#api-endpoints)
5. [Error Handling](#error-handling)
6. [Security Considerations](#security-considerations)
7. [Scalability Considerations](#scalability-considerations)

## Project Structure

```
src/
├── config/                 # Configuration files
│   ├── database.ts         # Database connection configuration
│   └── app.ts              # Express app configuration
├── controllers/            # Request handlers
├── dtos/                   # Data Transfer Objects
├── interfaces/             # TypeScript interfaces
├── middlewares/            # Custom middlewares
│   ├── auth.middleware.ts  # Authentication middleware
│   ├── error.middleware.ts # Error handling middleware
│   └── validation.middleware.ts # Request validation middleware
├── routes/                 # API routes
├── services/               # Business logic
├── utils/                  # Utility functions
└── server.ts               # Entry point
```

## Core Components

### Database Connection

```typescript
// src/config/database.ts
import mysql from 'mysql2/promise';

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'hostel_management',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

export default pool;
```

### Base Controller

```typescript
// src/controllers/base.controller.ts
import { Request, Response, NextFunction } from 'express';

export abstract class BaseController {
  protected abstract executeImpl(req: Request, res: Response, next: NextFunction): Promise<void | any>;

  public async execute(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await this.executeImpl(req, res, next);
    } catch (err) {
      next(err);
    }
  }

  public static jsonResponse(res: Response, code: number, message: string) {
    return res.status(code).json({ message });
  }

  public ok<T>(res: Response, dto?: T) {
    if (dto) {
      return res.status(200).json(dto);
    } else {
      return res.sendStatus(200);
    }
  }

  public created<T>(res: Response, dto?: T) {
    if (dto) {
      return res.status(201).json(dto);
    } else {
      return res.sendStatus(201);
    }
  }

  public badRequest(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 400, message || 'Bad request');
  }

  public unauthorized(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 401, message || 'Unauthorized');
  }

  public forbidden(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 403, message || 'Forbidden');
  }

  public notFound(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 404, message || 'Not found');
  }

  public conflict(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 409, message || 'Conflict');
  }

  public internalServerError(res: Response, message?: string) {
    return BaseController.jsonResponse(res, 500, message || 'Internal server error');
  }
}
```

### Error Handling Middleware

```typescript
// src/middlewares/error.middleware.ts
import { Request, Response, NextFunction } from 'express';

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;

  constructor(message: string, statusCode: number, isOperational: boolean = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      status: 'error',
      message: err.message
    });
  }

  console.error('ERROR 💥', err);
  return res.status(500).json({
    status: 'error',
    message: 'Something went wrong'
  });
};
```

## Authentication & Authorization

### Authentication Middleware

```typescript
// src/middlewares/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AppError } from './error.middleware';
import pool from '../config/database';

interface DecodedToken {
  id: number;
  role: string;
  iat: number;
  exp: number;
}

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        role: string;
      };
    }
  }
}

export const protect = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // 1) Get token and check if it exists
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }

    // 2) Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key') as DecodedToken;

    // 3) Check if user still exists
    const [rows] = await pool.execute(
      'SELECT user_id, role, is_active FROM users WHERE user_id = ?',
      [decoded.id]
    );
    
    const currentUser = (rows as any[])[0];
    
    if (!currentUser) {
      return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    if (!currentUser.is_active) {
      return next(new AppError('This user account has been deactivated.', 401));
    }

    // 4) Grant access to protected route
    req.user = {
      id: currentUser.user_id,
      role: currentUser.role
    };
    
    next();
  } catch (error) {
    next(new AppError('Invalid token. Please log in again.', 401));
  }
};

export const restrictTo = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }
    
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action.', 403));
    }
    
    next();
  };
};
```
## API Endpoints

### 1. User Management

#### 1.1 Authentication

##### Login
- **URL**: `POST /api/auth/login`
- **Description**: Authenticate a user and return a JWT token
- **Request Body**:
```typescript
interface LoginDto {
  username: string;
  password: string;
}
```
- **Response**:
```typescript
interface AuthResponseDto {
  token: string;
  user: {
    id: number;
    username: string;
    email: string;
    role: string;
    firstName: string;
    lastName: string;
  }
}
```
- **Status Codes**:
  - `200 OK`: Successful login
  - `401 Unauthorized`: Invalid credentials
- **Service Logic**:
```typescript
// src/services/auth.service.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/database';
import { AppError } from '../middlewares/error.middleware';

export class AuthService {
  async login(username: string, password: string) {
    // 1) Check if username and password exist
    if (!username || !password) {
      throw new AppError('Please provide username and password', 400);
    }

    // 2) Check if user exists && password is correct
    const [rows] = await pool.execute(
      'SELECT user_id, username, email, password, first_name, last_name, role, is_active FROM users WHERE username = ?',
      [username]
    );

    const users = rows as any[];
    if (users.length === 0) {
      throw new AppError('Invalid credentials', 401);
    }

    const user = users[0];
    
    if (!user.is_active) {
      throw new AppError('Your account has been deactivated', 401);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new AppError('Invalid credentials', 401);
    }

    // 3) If everything ok, send token to client
    const token = jwt.sign(
      { id: user.user_id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
    );

    // 4) Update last login time
    await pool.execute(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?',
      [user.user_id]
    );

    return {
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name
      }
    };
  }
}
```

##### Register (for admin to create users)
- **URL**: `POST /api/users`
- **Description**: Create a new user (admin only)
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateUserDto {
  username: string;
  password: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'student' | 'admin' | 'warden' | 'staff';
  phone?: string;
  address?: string;
  dateOfBirth?: string; // ISO format
  gender?: 'male' | 'female' | 'other';
}
```
- **Response**: Same as AuthResponseDto
- **Status Codes**:
  - `201 Created`: User created successfully
  - `400 Bad Request`: Invalid input
  - `409 Conflict`: Username or email already exists

#### 1.2 User CRUD Operations

##### Get All Users
- **URL**: `GET /api/users`
- **Description**: Get all users (admin only)
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `role`: Filter by role
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
  - `search`: Search by name, email, or username
- **Response**:
```typescript
interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

interface UserDto {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  phone?: string;
  isActive: boolean;
  lastLogin?: string;
  createdAt: string;
}

// Response type: PaginatedResponse<UserDto>
```
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized

##### Get User by ID
- **URL**: `GET /api/users/:id`
- **Description**: Get user details by ID
- **Auth Required**: Yes (admin or self)
- **Response**: UserDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: User not found

##### Update User
- **URL**: `PUT /api/users/:id`
- **Description**: Update user details
- **Auth Required**: Yes (admin or self)
- **Request Body**:
```typescript
interface UpdateUserDto {
  email?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  address?: string;
  dateOfBirth?: string;
  gender?: 'male' | 'female' | 'other';
  isActive?: boolean; // Admin only
  role?: 'student' | 'admin' | 'warden' | 'staff'; // Admin only
}
```
- **Response**: UserDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: User not found
  - `409 Conflict`: Email already exists

##### Delete User
- **URL**: `DELETE /api/users/:id`
- **Description**: Delete a user (admin only)
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: User not found

##### Change Password
- **URL**: `PATCH /api/users/:id/password`
- **Description**: Change user password
- **Auth Required**: Yes (admin or self)
- **Request Body**:
```typescript
interface ChangePasswordDto {
  currentPassword: string; // Required for non-admin users
  newPassword: string;
}
```
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `401 Unauthorized`: Current password is incorrect
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: User not found
### 2. Hostel Management

#### 2.1 Hostel CRUD Operations

##### Get All Hostels
- **URL**: `GET /api/hostels`
- **Description**: Get all hostels
- **Auth Required**: Yes
- **Query Parameters**:
  - `type`: Filter by hostel type (male/female/mixed)
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
  - `search`: Search by name
- **Response**:
```typescript
interface HostelDto {
  id: number;
  name: string;
  type: 'boys' | 'girls' | 'mixed';
  address: string;
  totalBlocks: number;
  description?: string;
  facilities?: Record<string, any>;
  contactNumber?: string;
  email?: string;
  warden?: {
    id: number;
    name: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<HostelDto>
```
- **Status Codes**:
  - `200 OK`: Success
- **Service Logic**:
```typescript
// src/services/hostel.service.ts
import pool from '../config/database';
import { AppError } from '../middlewares/error.middleware';

export class HostelService {
  async getAllHostels(options: {
    type?: string;
    page?: number;
    limit?: number;
    search?: string;
  }) {
    const { type, page = 1, limit = 10, search } = options;
    
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT h.hostel_id, h.hostel_name, h.hostel_type, h.address, h.total_blocks, 
             h.description, h.facilities, h.contact_number, h.email, h.created_at, h.updated_at,
             h.warden_id, CONCAT(u.first_name, ' ', u.last_name) as warden_name
      FROM hostels h
      LEFT JOIN users u ON h.warden_id = u.user_id
      WHERE 1=1
    `;
    
    const queryParams: any[] = [];
    
    if (type) {
      query += ' AND h.hostel_type = ?';
      queryParams.push(type);
    }
    
    if (search) {
      query += ' AND h.hostel_name LIKE ?';
      queryParams.push(`%${search}%`);
    }
    
    // Count total records
    const countQuery = query.replace('SELECT h.hostel_id, h.hostel_name', 'SELECT COUNT(*) as total');
    const [countRows] = await pool.execute(countQuery, queryParams);
    const total = (countRows as any[])[0].total;
    
    // Get paginated data
    query += ' ORDER BY h.hostel_name LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);
    
    const [rows] = await pool.execute(query, queryParams);
    
    const hostels = (rows as any[]).map(row => ({
      id: row.hostel_id,
      name: row.hostel_name,
      type: row.hostel_type,
      address: row.address,
      totalBlocks: row.total_blocks,
      description: row.description,
      facilities: row.facilities ? JSON.parse(row.facilities) : null,
      contactNumber: row.contact_number,
      email: row.email,
      warden: row.warden_id ? {
        id: row.warden_id,
        name: row.warden_name
      } : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
    
    return {
      data: hostels,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    };
  }
}
```

##### Get Hostel by ID
- **URL**: `GET /api/hostels/:id`
- **Description**: Get hostel details by ID
- **Auth Required**: Yes
- **Response**: HostelDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Hostel not found
- **Service Logic**:
```typescript
// In HostelService class
async getHostelById(id: number) {
  const [rows] = await pool.execute(
    `SELECT h.hostel_id, h.hostel_name, h.hostel_type, h.address, h.total_blocks, 
            h.description, h.facilities, h.contact_number, h.email, h.created_at, h.updated_at,
            h.warden_id, CONCAT(u.first_name, ' ', u.last_name) as warden_name
     FROM hostels h
     LEFT JOIN users u ON h.warden_id = u.user_id
     WHERE h.hostel_id = ?`,
    [id]
  );
  
  const hostels = rows as any[];
  if (hostels.length === 0) {
    throw new AppError('Hostel not found', 404);
  }
  
  const row = hostels[0];
  return {
    id: row.hostel_id,
    name: row.hostel_name,
    type: row.hostel_type,
    address: row.address,
    totalBlocks: row.total_blocks,
    description: row.description,
    facilities: row.facilities ? JSON.parse(row.facilities) : null,
    contactNumber: row.contact_number,
    email: row.email,
    warden: row.warden_id ? {
      id: row.warden_id,
      name: row.warden_name
    } : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}
```
##### Create Hostel
- **URL**: `POST /api/hostels`
- **Description**: Create a new hostel
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateHostelDto {
  name: string;
  type: 'boys' | 'girls' | 'mixed';
  address: string;
  totalBlocks: number;
  description?: string;
  facilities?: Record<string, any>;
  contactNumber?: string;
  email?: string;
  wardenId?: number;
}
```
- **Response**: HostelDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `409 Conflict`: Hostel name already exists
- **Service Logic**:
```typescript
// In HostelService class
async createHostel(data: CreateHostelDto) {
  // Check if hostel name already exists
  const [existingRows] = await pool.execute(
    'SELECT hostel_id FROM hostels WHERE hostel_name = ?',
    [data.name]
  );
  
  if ((existingRows as any[]).length > 0) {
    throw new AppError('Hostel with this name already exists', 409);
  }
  
  // If wardenId is provided, check if user exists and is a warden
  if (data.wardenId) {
    const [userRows] = await pool.execute(
      'SELECT user_id, role FROM users WHERE user_id = ?',
      [data.wardenId]
    );
    
    const users = userRows as any[];
    if (users.length === 0) {
      throw new AppError('Warden not found', 404);
    }
    
    if (users[0].role !== 'warden') {
      throw new AppError('Selected user is not a warden', 400);
    }
  }
  
  const facilitiesJson = data.facilities ? JSON.stringify(data.facilities) : null;
  
  const [result] = await pool.execute(
    `INSERT INTO hostels (
      hostel_name, hostel_type, address, total_blocks, description, 
      facilities, contact_number, email, warden_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      data.name, data.type, data.address, data.totalBlocks, data.description || null,
      facilitiesJson, data.contactNumber || null, data.email || null, data.wardenId || null
    ]
  );
  
  const insertId = (result as any).insertId;
  
  return this.getHostelById(insertId);
}
```

##### Update Hostel
- **URL**: `PUT /api/hostels/:id`
- **Description**: Update hostel details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateHostelDto {
  name?: string;
  type?: 'boys' | 'girls' | 'mixed';
  address?: string;
  totalBlocks?: number;
  description?: string;
  facilities?: Record<string, any>;
  contactNumber?: string;
  email?: string;
  wardenId?: number | null;
}
```
- **Response**: HostelDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Hostel not found
  - `409 Conflict`: Hostel name already exists
- **Service Logic**:
```typescript
// In HostelService class
async updateHostel(id: number, data: UpdateHostelDto) {
  // Check if hostel exists
  const [existingRows] = await pool.execute(
    'SELECT hostel_id FROM hostels WHERE hostel_id = ?',
    [id]
  );
  
  if ((existingRows as any[]).length === 0) {
    throw new AppError('Hostel not found', 404);
  }
  
  // If name is being updated, check if it's unique
  if (data.name) {
    const [nameRows] = await pool.execute(
      'SELECT hostel_id FROM hostels WHERE hostel_name = ? AND hostel_id != ?',
      [data.name, id]
    );
    
    if ((nameRows as any[]).length > 0) {
      throw new AppError('Hostel with this name already exists', 409);
    }
  }
  
  // If wardenId is provided, check if user exists and is a warden
  if (data.wardenId) {
    const [userRows] = await pool.execute(
      'SELECT user_id, role FROM users WHERE user_id = ?',
      [data.wardenId]
    );
    
    const users = userRows as any[];
    if (users.length === 0) {
      throw new AppError('Warden not found', 404);
    }
    
    if (users[0].role !== 'warden') {
      throw new AppError('Selected user is not a warden', 400);
    }
  }
  
  // Build update query dynamically
  const updates: string[] = [];
  const values: any[] = [];
  
  if (data.name !== undefined) {
    updates.push('hostel_name = ?');
    values.push(data.name);
  }
  
  if (data.type !== undefined) {
    updates.push('hostel_type = ?');
    values.push(data.type);
  }
  
  if (data.address !== undefined) {
    updates.push('address = ?');
    values.push(data.address);
  }
  
  if (data.totalBlocks !== undefined) {
    updates.push('total_blocks = ?');
    values.push(data.totalBlocks);
  }
  
  if (data.description !== undefined) {
    updates.push('description = ?');
    values.push(data.description);
  }
  
  if (data.facilities !== undefined) {
    updates.push('facilities = ?');
    values.push(JSON.stringify(data.facilities));
  }
  
  if (data.contactNumber !== undefined) {
    updates.push('contact_number = ?');
    values.push(data.contactNumber);
  }
  
  if (data.email !== undefined) {
    updates.push('email = ?');
    values.push(data.email);
  }
  
  if (data.wardenId !== undefined) {
    updates.push('warden_id = ?');
    values.push(data.wardenId);
  }
  
  if (updates.length === 0) {
    return this.getHostelById(id);
  }
  
  values.push(id);
  
  await pool.execute(
    `UPDATE hostels SET ${updates.join(', ')} WHERE hostel_id = ?`,
    values
  );
  
  return this.getHostelById(id);
}
```
##### Delete Hostel
- **URL**: `DELETE /api/hostels/:id`
- **Description**: Delete a hostel
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `404 Not Found`: Hostel not found
  - `409 Conflict`: Cannot delete hostel with active blocks/students
- **Service Logic**:
```typescript
// In HostelService class
async deleteHostel(id: number) {
  // Check if hostel exists
  const [existingRows] = await pool.execute(
    'SELECT hostel_id FROM hostels WHERE hostel_id = ?',
    [id]
  );
  
  if ((existingRows as any[]).length === 0) {
    throw new AppError('Hostel not found', 404);
  }
  
  // Check if hostel has blocks
  const [blockRows] = await pool.execute(
    'SELECT COUNT(*) as count FROM blocks WHERE hostel_id = ?',
    [id]
  );
  
  if ((blockRows as any[])[0].count > 0) {
    throw new AppError('Cannot delete hostel with existing blocks. Delete blocks first.', 409);
  }
  
  await pool.execute('DELETE FROM hostels WHERE hostel_id = ?', [id]);
}
```

#### 2.2 Block Management

##### Get All Blocks
- **URL**: `GET /api/hostels/:hostelId/blocks`
- **Description**: Get all blocks in a hostel
- **Auth Required**: Yes
- **Query Parameters**:
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface BlockDto {
  id: number;
  hostelId: number;
  name: string;
  code: string;
  totalFloors: number;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<BlockDto>
```
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Hostel not found

##### Get Block by ID
- **URL**: `GET /api/blocks/:id`
- **Description**: Get block details by ID
- **Auth Required**: Yes
- **Response**: BlockDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Block not found

##### Create Block
- **URL**: `POST /api/hostels/:hostelId/blocks`
- **Description**: Create a new block in a hostel
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateBlockDto {
  name: string;
  code: string;
  totalFloors: number;
  description?: string;
}
```
- **Response**: BlockDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Hostel not found
  - `409 Conflict`: Block name or code already exists

##### Update Block
- **URL**: `PUT /api/blocks/:id`
- **Description**: Update block details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateBlockDto {
  name?: string;
  code?: string;
  totalFloors?: number;
  description?: string;
}
```
- **Response**: BlockDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Block not found
  - `409 Conflict`: Block name or code already exists

##### Delete Block
- **URL**: `DELETE /api/blocks/:id`
- **Description**: Delete a block
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `404 Not Found`: Block not found
  - `409 Conflict`: Cannot delete block with active floors/rooms
### 3. Room Management

#### 3.1 Floor Management

##### Get All Floors
- **URL**: `GET /api/blocks/:blockId/floors`
- **Description**: Get all floors in a block
- **Auth Required**: Yes
- **Query Parameters**:
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface FloorDto {
  id: number;
  blockId: number;
  floorNumber: number;
  floorName?: string;
  totalRooms: number;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<FloorDto>
```
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Block not found

##### Get Floor by ID
- **URL**: `GET /api/floors/:id`
- **Description**: Get floor details by ID
- **Auth Required**: Yes
- **Response**: FloorDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Floor not found

##### Create Floor
- **URL**: `POST /api/blocks/:blockId/floors`
- **Description**: Create a new floor in a block
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateFloorDto {
  floorNumber: number;
  floorName?: string;
  totalRooms: number;
  description?: string;
}
```
- **Response**: FloorDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Block not found
  - `409 Conflict`: Floor number already exists in this block

##### Update Floor
- **URL**: `PUT /api/floors/:id`
- **Description**: Update floor details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateFloorDto {
  floorNumber?: number;
  floorName?: string;
  totalRooms?: number;
  description?: string;
}
```
- **Response**: FloorDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Floor not found
  - `409 Conflict`: Floor number already exists in this block

##### Delete Floor
- **URL**: `DELETE /api/floors/:id`
- **Description**: Delete a floor
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `404 Not Found`: Floor not found
  - `409 Conflict`: Cannot delete floor with active rooms

#### 3.2 Room Management

##### Get All Rooms
- **URL**: `GET /api/floors/:floorId/rooms`
- **Description**: Get all rooms on a floor
- **Auth Required**: Yes
- **Query Parameters**:
  - `status`: Filter by status (available/occupied/maintenance/reserved)
  - `type`: Filter by room type (single/double/triple/quad)
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface RoomDto {
  id: number;
  floorId: number;
  roomNumber: string;
  roomType: 'single' | 'double' | 'triple' | 'quad';
  capacity: number;
  currentOccupancy: number;
  status: 'available' | 'occupied' | 'maintenance' | 'reserved';
  monthlyRent: number;
  facilities?: Record<string, any>;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<RoomDto>
```
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Floor not found

##### Get Room by ID
- **URL**: `GET /api/rooms/:id`
- **Description**: Get room details by ID
- **Auth Required**: Yes
- **Response**: RoomDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Room not found

##### Create Room
- **URL**: `POST /api/floors/:floorId/rooms`
- **Description**: Create a new room on a floor
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateRoomDto {
  roomNumber: string;
  roomType: 'single' | 'double' | 'triple' | 'quad';
  capacity: number;
  monthlyRent: number;
  facilities?: Record<string, any>;
  description?: string;
  status?: 'available' | 'maintenance' | 'reserved';
}
```
- **Response**: RoomDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Floor not found
  - `409 Conflict`: Room number already exists on this floor

##### Update Room
- **URL**: `PUT /api/rooms/:id`
- **Description**: Update room details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateRoomDto {
  roomNumber?: string;
  roomType?: 'single' | 'double' | 'triple' | 'quad';
  capacity?: number;
  monthlyRent?: number;
  facilities?: Record<string, any>;
  description?: string;
  status?: 'available' | 'occupied' | 'maintenance' | 'reserved';
}
```
- **Response**: RoomDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Room not found
  - `409 Conflict`: Room number already exists on this floor or cannot change occupied room
##### Delete Room
- **URL**: `DELETE /api/rooms/:id`
- **Description**: Delete a room
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `404 Not Found`: Room not found
  - `409 Conflict`: Cannot delete occupied room

##### Get Room Occupants
- **URL**: `GET /api/rooms/:id/occupants`
- **Description**: Get students currently allocated to a room
- **Auth Required**: Yes
- **Response**:
```typescript
interface StudentBasicDto {
  id: number;
  userId: number;
  registrationNumber: string;
  firstName: string;
  lastName: string;
  department: string;
  program: string;
  academicYear: number;
  allocationId: number;
  checkInDate: string;
  expectedCheckOutDate?: string;
  bedNumber?: number;
}

// Response type: StudentBasicDto[]
```
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Room not found

#### 3.3 Room Allocation

##### Get All Room Allocations
- **URL**: `GET /api/room-allocations`
- **Description**: Get all room allocations
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `status`: Filter by status (active/upcoming/completed/cancelled)
  - `studentId`: Filter by student ID
  - `roomId`: Filter by room ID
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface RoomAllocationDto {
  id: number;
  roomId: number;
  roomNumber: string;
  hostelName: string;
  blockName: string;
  floorNumber: number;
  studentId: number;
  studentName: string;
  registrationNumber: string;
  checkInDate: string;
  expectedCheckOutDate?: string;
  actualCheckOutDate?: string;
  allocationStatus: 'active' | 'upcoming' | 'completed' | 'cancelled';
  bedNumber?: number;
  monthlyRent: number;
  securityDeposit: number;
  allocationNotes?: string;
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<RoomAllocationDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Room Allocation by ID
- **URL**: `GET /api/room-allocations/:id`
- **Description**: Get room allocation details by ID
- **Auth Required**: Yes (admin or allocated student)
- **Response**: RoomAllocationDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Allocation not found

##### Create Room Allocation
- **URL**: `POST /api/room-allocations`
- **Description**: Allocate a room to a student
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateRoomAllocationDto {
  roomId: number;
  studentId: number;
  checkInDate: string; // ISO format
  expectedCheckOutDate?: string; // ISO format
  allocationStatus?: 'active' | 'upcoming';
  bedNumber?: number;
  monthlyRent: number;
  securityDeposit: number;
  allocationNotes?: string;
}
```
- **Response**: RoomAllocationDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Room or student not found
  - `409 Conflict`: Room is full or student already has an active allocation
- **Service Logic**:
```typescript
// src/services/room-allocation.service.ts
import pool from '../config/database';
import { AppError } from '../middlewares/error.middleware';

export class RoomAllocationService {
  async createRoomAllocation(data: CreateRoomAllocationDto, userId: number) {
    // Check if room exists and has capacity
    const [roomRows] = await pool.execute(
      `SELECT r.room_id, r.capacity, r.current_occupancy, r.status, r.room_type,
              f.floor_id, f.floor_number, b.block_id, b.block_name, h.hostel_id, h.hostel_name
       FROM rooms r
       JOIN floors f ON r.floor_id = f.floor_id
       JOIN blocks b ON f.block_id = b.block_id
       JOIN hostels h ON b.hostel_id = h.hostel_id
       WHERE r.room_id = ?`,
      [data.roomId]
    );
    
    const rooms = roomRows as any[];
    if (rooms.length === 0) {
      throw new AppError('Room not found', 404);
    }
    
    const room = rooms[0];
    
    if (room.status !== 'available' && room.status !== 'occupied') {
      throw new AppError('Room is not available for allocation', 400);
    }
    
    if (room.current_occupancy >= room.capacity) {
      throw new AppError('Room is already at full capacity', 409);
    }
    
    // Check if student exists
    const [studentRows] = await pool.execute(
      `SELECT s.student_id, s.registration_number, u.first_name, u.last_name, u.gender
       FROM students s
       JOIN users u ON s.user_id = u.user_id
       WHERE s.student_id = ?`,
      [data.studentId]
    );
    
    const students = studentRows as any[];
    if (students.length === 0) {
      throw new AppError('Student not found', 404);
    }
    
    const student = students[0];
    
    // Check if student already has an active allocation
    const [allocationRows] = await pool.execute(
      `SELECT allocation_id FROM room_allocations 
       WHERE student_id = ? AND allocation_status IN ('active', 'upcoming')`,
      [data.studentId]
    );
    
    if ((allocationRows as any[]).length > 0) {
      throw new AppError('Student already has an active room allocation', 409);
    }
    
    // Check if hostel type matches student gender
    const [hostelRows] = await pool.execute(
      'SELECT hostel_type FROM hostels WHERE hostel_id = ?',
      [room.hostel_id]
    );
    
    const hostel = (hostelRows as any[])[0];
    if (
      (hostel.hostel_type === 'boys' && student.gender !== 'male') ||
      (hostel.hostel_type === 'girls' && student.gender !== 'female')
    ) {
      throw new AppError('Student gender does not match hostel type', 400);
    }
    
    // Create allocation
    const [result] = await pool.execute(
      `INSERT INTO room_allocations (
        room_id, student_id, check_in_date, expected_check_out_date,
        allocation_status, bed_number, monthly_rent, security_deposit,
        allocation_notes, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        data.roomId,
        data.studentId,
        data.checkInDate,
        data.expectedCheckOutDate || null,
        data.allocationStatus || 'active',
        data.bedNumber || null,
        data.monthlyRent,
        data.securityDeposit,
        data.allocationNotes || null,
        userId
      ]
    );
    
    const insertId = (result as any).insertId;
    
    // Update room occupancy if allocation is active
    if (data.allocationStatus !== 'upcoming') {
      await pool.execute(
        'UPDATE rooms SET current_occupancy = current_occupancy + 1, status = IF(current_occupancy + 1 >= capacity, "occupied", status) WHERE room_id = ?',
        [data.roomId]
      );
    }
    
    // Return the created allocation
    const [newAllocationRows] = await pool.execute(
      `SELECT ra.*, r.room_number, h.hostel_name, b.block_name, f.floor_number,
              CONCAT(u.first_name, ' ', u.last_name) as student_name, s.registration_number
       FROM room_allocations ra
       JOIN rooms r ON ra.room_id = r.room_id
       JOIN floors f ON r.floor_id = f.floor_id
       JOIN blocks b ON f.block_id = b.block_id
       JOIN hostels h ON b.hostel_id = h.hostel_id
       JOIN students s ON ra.student_id = s.student_id
       JOIN users u ON s.user_id = u.user_id
       WHERE ra.allocation_id = ?`,
      [insertId]
    );
    
    const allocation = (newAllocationRows as any[])[0];
    
    return {
      id: allocation.allocation_id,
      roomId: allocation.room_id,
      roomNumber: allocation.room_number,
      hostelName: allocation.hostel_name,
      blockName: allocation.block_name,
      floorNumber: allocation.floor_number,
      studentId: allocation.student_id,
      studentName: allocation.student_name,
      registrationNumber: allocation.registration_number,
      checkInDate: allocation.check_in_date,
      expectedCheckOutDate: allocation.expected_check_out_date,
      actualCheckOutDate: allocation.actual_check_out_date,
      allocationStatus: allocation.allocation_status,
      bedNumber: allocation.bed_number,
      monthlyRent: allocation.monthly_rent,
      securityDeposit: allocation.security_deposit,
      allocationNotes: allocation.allocation_notes,
      createdAt: allocation.created_at,
      updatedAt: allocation.updated_at
    };
  }
}
```
##### Update Room Allocation
- **URL**: `PUT /api/room-allocations/:id`
- **Description**: Update room allocation details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateRoomAllocationDto {
  expectedCheckOutDate?: string; // ISO format
  allocationStatus?: 'active' | 'upcoming' | 'completed' | 'cancelled';
  actualCheckOutDate?: string; // ISO format, required if status is 'completed'
  bedNumber?: number;
  monthlyRent?: number;
  allocationNotes?: string;
}
```
- **Response**: RoomAllocationDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Allocation not found
  - `409 Conflict`: Cannot update completed or cancelled allocation

##### Check Out Student
- **URL**: `POST /api/room-allocations/:id/check-out`
- **Description**: Check out a student from their room
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CheckOutDto {
  actualCheckOutDate: string; // ISO format
  notes?: string;
}
```
- **Response**: RoomAllocationDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Allocation not found
  - `409 Conflict`: Allocation is not active

### 4. Student Management

#### 4.1 Student CRUD Operations

##### Get All Students
- **URL**: `GET /api/students`
- **Description**: Get all students
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `department`: Filter by department
  - `program`: Filter by program
  - `academicYear`: Filter by academic year
  - `search`: Search by name, email, or registration number
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface StudentDto {
  id: number;
  userId: number;
  registrationNumber: string;
  firstName: string;
  lastName: string;
  email: string;
  phone?: string;
  department: string;
  program: string;
  academicYear: number;
  admissionDate: string;
  guardianName?: string;
  guardianPhone?: string;
  guardianEmail?: string;
  bloodGroup?: string;
  gender?: string;
  currentRoom?: {
    id: number;
    roomNumber: string;
    hostelName: string;
    blockName: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<StudentDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Student by ID
- **URL**: `GET /api/students/:id`
- **Description**: Get student details by ID
- **Auth Required**: Yes (admin or self)
- **Response**: StudentDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Student not found

##### Create Student
- **URL**: `POST /api/students`
- **Description**: Create a new student (creates user account as well)
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateStudentDto {
  // User information
  username: string;
  password: string;
  email: string;
  firstName: string;
  lastName: string;
  phone?: string;
  address?: string;
  dateOfBirth?: string; // ISO format
  gender?: 'male' | 'female' | 'other';
  
  // Student information
  registrationNumber: string;
  department: string;
  program: string;
  academicYear: number;
  admissionDate: string; // ISO format
  guardianName?: string;
  guardianPhone?: string;
  guardianEmail?: string;
  guardianAddress?: string;
  bloodGroup?: string;
  medicalConditions?: string;
}
```
- **Response**: StudentDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `409 Conflict`: Username, email, or registration number already exists

##### Update Student
- **URL**: `PUT /api/students/:id`
- **Description**: Update student details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateStudentDto {
  // User information
  email?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  address?: string;
  dateOfBirth?: string; // ISO format
  gender?: 'male' | 'female' | 'other';
  
  // Student information
  department?: string;
  program?: string;
  academicYear?: number;
  guardianName?: string;
  guardianPhone?: string;
  guardianEmail?: string;
  guardianAddress?: string;
  bloodGroup?: string;
  medicalConditions?: string;
}
```
- **Response**: StudentDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Student not found
  - `409 Conflict`: Email already exists
### 5. Mess Management

#### 5.1 Mess CRUD Operations

##### Get All Mess Facilities
- **URL**: `GET /api/mess`
- **Description**: Get all mess facilities
- **Auth Required**: Yes
- **Query Parameters**:
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface MessDto {
  id: number;
  name: string;
  location: string;
  capacity: number;
  contactNumber?: string;
  email?: string;
  operatingHours: Record<string, string>;
  description?: string;
  manager?: {
    id: number;
    name: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<MessDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Mess by ID
- **URL**: `GET /api/mess/:id`
- **Description**: Get mess details by ID
- **Auth Required**: Yes
- **Response**: MessDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Mess not found

##### Create Mess
- **URL**: `POST /api/mess`
- **Description**: Create a new mess facility
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateMessDto {
  name: string;
  location: string;
  capacity: number;
  contactNumber?: string;
  email?: string;
  operatingHours: Record<string, string>;
  description?: string;
  managerId?: number;
}
```
- **Response**: MessDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `409 Conflict`: Mess name already exists

##### Update Mess
- **URL**: `PUT /api/mess/:id`
- **Description**: Update mess details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateMessDto {
  name?: string;
  location?: string;
  capacity?: number;
  contactNumber?: string;
  email?: string;
  operatingHours?: Record<string, string>;
  description?: string;
  managerId?: number | null;
}
```
- **Response**: MessDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Mess not found
  - `409 Conflict`: Mess name already exists

##### Delete Mess
- **URL**: `DELETE /api/mess/:id`
- **Description**: Delete a mess facility
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `404 Not Found`: Mess not found
  - `409 Conflict`: Cannot delete mess with active subscriptions

#### 5.2 Mess Subscriptions

##### Get All Mess Subscriptions
- **URL**: `GET /api/mess-subscriptions`
- **Description**: Get all mess subscriptions
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `messId`: Filter by mess ID
  - `studentId`: Filter by student ID
  - `status`: Filter by status (active/expired/cancelled)
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface MessSubscriptionDto {
  id: number;
  studentId: number;
  studentName: string;
  registrationNumber: string;
  messId: number;
  messName: string;
  subscriptionType: 'daily' | 'weekly' | 'monthly' | 'semester';
  mealPlan: 'veg' | 'non-veg' | 'special';
  startDate: string;
  endDate: string;
  status: 'active' | 'expired' | 'cancelled';
  monthlyFee: number;
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<MessSubscriptionDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Student's Mess Subscription
- **URL**: `GET /api/students/:studentId/mess-subscription`
- **Description**: Get a student's current mess subscription
- **Auth Required**: Yes (admin or self)
- **Response**: MessSubscriptionDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Student or subscription not found

##### Create Mess Subscription
- **URL**: `POST /api/mess-subscriptions`
- **Description**: Create a new mess subscription for a student
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateMessSubscriptionDto {
  studentId: number;
  messId: number;
  subscriptionType: 'daily' | 'weekly' | 'monthly' | 'semester';
  mealPlan: 'veg' | 'non-veg' | 'special';
  startDate: string; // ISO format
  endDate: string; // ISO format
  monthlyFee: number;
}
```
- **Response**: MessSubscriptionDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Student or mess not found
  - `409 Conflict`: Student already has an active subscription

##### Update Mess Subscription
- **URL**: `PUT /api/mess-subscriptions/:id`
- **Description**: Update mess subscription details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateMessSubscriptionDto {
  subscriptionType?: 'daily' | 'weekly' | 'monthly' | 'semester';
  mealPlan?: 'veg' | 'non-veg' | 'special';
  endDate?: string; // ISO format
  status?: 'active' | 'expired' | 'cancelled';
  monthlyFee?: number;
}
```
- **Response**: MessSubscriptionDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Subscription not found
### 6. Complaint Management

#### 6.1 Complaints CRUD Operations

##### Get All Complaints
- **URL**: `GET /api/complaints`
- **Description**: Get all complaints
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `studentId`: Filter by student ID
  - `roomId`: Filter by room ID
  - `type`: Filter by complaint type
  - `status`: Filter by status
  - `priority`: Filter by priority
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface ComplaintDto {
  id: number;
  studentId: number;
  studentName: string;
  roomId?: number;
  roomNumber?: string;
  complaintType: 'maintenance' | 'cleanliness' | 'security' | 'mess' | 'other';
  subject: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  status: 'pending' | 'in_progress' | 'resolved' | 'closed' | 'rejected';
  submittedDate: string;
  resolvedDate?: string;
  resolutionNotes?: string;
  assignedTo?: {
    id: number;
    name: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<ComplaintDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Student's Complaints
- **URL**: `GET /api/students/:studentId/complaints`
- **Description**: Get complaints submitted by a student
- **Auth Required**: Yes (admin or self)
- **Query Parameters**:
  - `status`: Filter by status
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**: PaginatedResponse<ComplaintDto>
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Student not found

##### Get Complaint by ID
- **URL**: `GET /api/complaints/:id`
- **Description**: Get complaint details by ID
- **Auth Required**: Yes (admin, assigned staff, or complaint owner)
- **Response**: ComplaintDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Complaint not found

##### Create Complaint
- **URL**: `POST /api/complaints`
- **Description**: Submit a new complaint
- **Auth Required**: Yes
- **Request Body**:
```typescript
interface CreateComplaintDto {
  roomId?: number;
  complaintType: 'maintenance' | 'cleanliness' | 'security' | 'mess' | 'other';
  subject: string;
  description: string;
  priority?: 'low' | 'medium' | 'high' | 'urgent';
}
```
- **Response**: ComplaintDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Room not found

##### Update Complaint
- **URL**: `PUT /api/complaints/:id`
- **Description**: Update complaint details (admin or assigned staff)
- **Auth Required**: Yes (admin or assigned staff)
- **Request Body**:
```typescript
interface UpdateComplaintDto {
  priority?: 'low' | 'medium' | 'high' | 'urgent';
  status?: 'pending' | 'in_progress' | 'resolved' | 'closed' | 'rejected';
  resolutionNotes?: string;
  assignedTo?: number | null;
  resolvedDate?: string | null; // ISO format, required if status is 'resolved'
}
```
- **Response**: ComplaintDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Complaint not found

##### Delete Complaint
- **URL**: `DELETE /api/complaints/:id`
- **Description**: Delete a complaint (admin only)
- **Auth Required**: Yes (admin role)
- **Status Codes**:
  - `204 No Content`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Complaint not found

### 7. Payment Management

#### 7.1 Payments CRUD Operations

##### Get All Payments
- **URL**: `GET /api/payments`
- **Description**: Get all payments
- **Auth Required**: Yes (admin role)
- **Query Parameters**:
  - `studentId`: Filter by student ID
  - `paymentType`: Filter by payment type
  - `status`: Filter by status
  - `startDate`: Filter by payment date (start)
  - `endDate`: Filter by payment date (end)
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface PaymentDto {
  id: number;
  studentId: number;
  studentName: string;
  registrationNumber: string;
  paymentType: 'room_rent' | 'mess_fee' | 'security_deposit' | 'fine' | 'other';
  amount: number;
  paymentDate: string;
  paymentMethod: 'cash' | 'card' | 'bank_transfer' | 'upi' | 'other';
  transactionId?: string;
  referenceId?: number;
  referenceType?: 'room_allocation' | 'mess_subscription' | 'fine' | 'other';
  paymentStatus: 'pending' | 'completed' | 'failed' | 'refunded';
  receiptNumber?: string;
  paymentNotes?: string;
  createdBy: {
    id: number;
    name: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<PaymentDto>
```
- **Status Codes**:
  - `200 OK`: Success
##### Get Student's Payments
- **URL**: `GET /api/students/:studentId/payments`
- **Description**: Get payments made by a student
- **Auth Required**: Yes (admin or self)
- **Query Parameters**:
  - `paymentType`: Filter by payment type
  - `status`: Filter by status
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**: PaginatedResponse<PaymentDto>
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Student not found

##### Get Payment by ID
- **URL**: `GET /api/payments/:id`
- **Description**: Get payment details by ID
- **Auth Required**: Yes (admin or payment owner)
- **Response**: PaymentDto
- **Status Codes**:
  - `200 OK`: Success
  - `403 Forbidden`: Not authorized
  - `404 Not Found`: Payment not found

##### Create Payment
- **URL**: `POST /api/payments`
- **Description**: Record a new payment
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreatePaymentDto {
  studentId: number;
  paymentType: 'room_rent' | 'mess_fee' | 'security_deposit' | 'fine' | 'other';
  amount: number;
  paymentDate: string; // ISO format
  paymentMethod: 'cash' | 'card' | 'bank_transfer' | 'upi' | 'other';
  transactionId?: string;
  referenceId?: number;
  referenceType?: 'room_allocation' | 'mess_subscription' | 'fine' | 'other';
  paymentStatus?: 'pending' | 'completed' | 'failed' | 'refunded';
  receiptNumber?: string;
  paymentNotes?: string;
}
```
- **Response**: PaymentDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Student not found
  - `409 Conflict`: Receipt number already exists

##### Update Payment
- **URL**: `PUT /api/payments/:id`
- **Description**: Update payment details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdatePaymentDto {
  paymentStatus?: 'pending' | 'completed' | 'failed' | 'refunded';
  transactionId?: string;
  paymentNotes?: string;
}
```
- **Response**: PaymentDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Payment not found

#### 7.2 Fee Structure Management

##### Get All Fee Structures
- **URL**: `GET /api/fees-structure`
- **Description**: Get all fee structures
- **Auth Required**: Yes
- **Query Parameters**:
  - `feeType`: Filter by fee type
  - `roomType`: Filter by room type
  - `hostelId`: Filter by hostel ID
  - `academicYear`: Filter by academic year
  - `isActive`: Filter by active status
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 10)
- **Response**:
```typescript
interface FeeStructureDto {
  id: number;
  feeType: 'room_rent' | 'mess_fee' | 'security_deposit' | 'admission_fee' | 'other';
  roomType?: 'single' | 'double' | 'triple' | 'quad' | 'all';
  hostelId?: number;
  hostelName?: string;
  academicYear: number;
  semester?: 'odd' | 'even' | 'both';
  amount: number;
  frequency: 'one_time' | 'monthly' | 'semester' | 'yearly';
  description?: string;
  isActive: boolean;
  createdBy: {
    id: number;
    name: string;
  };
  createdAt: string;
  updatedAt: string;
}

// Response type: PaginatedResponse<FeeStructureDto>
```
- **Status Codes**:
  - `200 OK`: Success

##### Get Fee Structure by ID
- **URL**: `GET /api/fees-structure/:id`
- **Description**: Get fee structure details by ID
- **Auth Required**: Yes
- **Response**: FeeStructureDto
- **Status Codes**:
  - `200 OK`: Success
  - `404 Not Found`: Fee structure not found

##### Create Fee Structure
- **URL**: `POST /api/fees-structure`
- **Description**: Create a new fee structure
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface CreateFeeStructureDto {
  feeType: 'room_rent' | 'mess_fee' | 'security_deposit' | 'admission_fee' | 'other';
  roomType?: 'single' | 'double' | 'triple' | 'quad' | 'all';
  hostelId?: number;
  academicYear: number;
  semester?: 'odd' | 'even' | 'both';
  amount: number;
  frequency: 'one_time' | 'monthly' | 'semester' | 'yearly';
  description?: string;
  isActive?: boolean;
}
```
- **Response**: FeeStructureDto
- **Status Codes**:
  - `201 Created`: Success
  - `400 Bad Request`: Invalid input
  - `409 Conflict`: Fee structure with same parameters already exists

##### Update Fee Structure
- **URL**: `PUT /api/fees-structure/:id`
- **Description**: Update fee structure details
- **Auth Required**: Yes (admin role)
- **Request Body**:
```typescript
interface UpdateFeeStructureDto {
  amount?: number;
  description?: string;
  isActive?: boolean;
}
```
- **Response**: FeeStructureDto
- **Status Codes**:
  - `200 OK`: Success
  - `400 Bad Request`: Invalid input
  - `404 Not Found`: Fee structure not found
## Error Handling

The API uses a consistent error handling approach:

1. **Operational Errors**: Expected errors like invalid inputs, not found resources, etc.
2. **Programming Errors**: Unexpected errors like database connection issues, code bugs, etc.

### Error Response Format

```json
{
  "status": "error",
  "message": "Error message describing what went wrong"
}
```

### HTTP Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `204 No Content`: Request successful, no content to return
- `400 Bad Request`: Invalid input, validation errors
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Authenticated but not authorized
- `404 Not Found`: Resource not found
- `409 Conflict`: Request conflicts with current state
- `500 Internal Server Error`: Server-side error

## Security Considerations

### Authentication

- JWT-based authentication
- Tokens expire after a configurable time (default: 24 hours)
- Refresh token mechanism for extended sessions

### Authorization

- Role-based access control (RBAC)
- Endpoint-level permission checks
- Resource ownership validation

### Input Validation

- Request body validation using middleware
- Sanitization of inputs to prevent SQL injection
- Parameter validation for query parameters

### Data Protection

- Password hashing using bcrypt
- HTTPS for all API communications
- Sensitive data encryption in transit and at rest

### Rate Limiting

- API rate limiting to prevent abuse
- Graduated rate limits based on endpoint sensitivity

## Scalability Considerations

### Database Optimization

- Connection pooling for efficient database connections
- Prepared statements for all SQL queries
- Indexing strategy for frequently queried columns
- Query optimization for complex joins

### Performance

- Pagination for list endpoints
- Selective field retrieval where appropriate
- Caching for frequently accessed, rarely changing data
- Compression for API responses

### Horizontal Scaling

- Stateless API design for easy horizontal scaling
- Database read replicas for scaling read operations
- Load balancing across multiple API instances

## Implementation Notes

### Database Transactions

For operations that modify multiple tables, use transactions to ensure data consistency:

```typescript
// Example transaction
const connection = await pool.getConnection();
try {
  await connection.beginTransaction();
  
  // Multiple database operations
  
  await connection.commit();
  return result;
} catch (error) {
  await connection.rollback();
  throw error;
} finally {
  connection.release();
}
```

### Logging

Implement structured logging for easier debugging and monitoring:

```typescript
// src/utils/logger.ts
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

export default logger;
```

### API Documentation

Use Swagger/OpenAPI for API documentation:

```typescript
// src/config/swagger.ts
import swaggerJSDoc from 'swagger-jsdoc';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Hostel Management System API',
      version: '1.0.0',
      description: 'API documentation for Hostel Management System'
    },
    servers: [
      {
        url: '/api',
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ['./src/routes/*.ts']
};

const swaggerSpec = swaggerJSDoc(options);

export default swaggerSpec;
```
