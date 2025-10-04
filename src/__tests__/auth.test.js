// src/__tests__/auth.test.js
import request from 'supertest';
import app from '../app.js'; // Your main Express app
import User from '../models/user.model.js'; // Your User model (assuming Mongoose)
import redisService from '../config/redis.js'; // Your Redis service
import * as userService from '../services/user.service.js'; // Import for mocking if needed
import { sendVerificationEmail } from '../utils/sendEmail.js'; // For mocking

// Mock the email sender to avoid actual emails
jest.mock('../utils/sendEmail.js');
const mockedSendVerificationEmail = sendVerificationEmail as jest.MockedFunction<typeof sendVerificationEmail>;

// Global cleanup
afterEach(async () => {
  // Clean up database
  await User.deleteMany({ username: { $regex: '^test' } }); // Delete test users
  // Clean up Redis (flush all test keys; in production, be more targeted)
  const keys = await redisService.keys('refreshToken:*');
  if (keys.length > 0) {
    await redisService.del(keys);
  }
  // Clear mocks
  mockedSendVerificationEmail.mockClear();
});

describe('Auth API Routes', () => {
  // Test for User Registration
  describe('POST /api/v1/auth/register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe(userData.email);
      expect(response.body.data.username).toBe(userData.username);
      expect(response.body.data).not.toHaveProperty('password');
      expect(response.body.accessToken).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();

      // Verify cookies are set
      const cookies = response.headers['set-cookie'] || [];
      expect(cookies.some((cookie) => cookie.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((cookie) => cookie.startsWith('refreshToken='))).toBe(true);

      // Verify user in database
      const dbUser  = await User.findOne({ email: userData.email });
      expect(dbUser ).not.toBeNull();
      expect(dbUser .username).toBe(userData.username);

      // Verify refresh token in Redis
      const redisToken = await redisService.get(`refreshToken:${dbUser ._id}`);
      expect(redisToken).toBe(response.body.refreshToken);
    });

    it('should return 400 if email already exists', async () => {
      // First, create a user
      await User.create({
        username: 'existinguser',
        email: 'exists@example.com',
        password: 'Password123!',
      });

      const userData = {
        username: 'newuser',
        email: 'exists@example.com', // Duplicate email
        password: 'Password456!',
        name: 'New User',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(400); // Assuming service throws 400 for duplicate

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Email already registered'); // Match your service error
    });

    it('should return 400 for invalid registration data (e.g., missing email)', async () => {
      const userData = {
        username: 'testuserInvalid',
        // email is missing
        password: 'Password123!',
        name: 'Test User Invalid',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(400); // Joi validation error

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('email') && expect(response.body.message).toContain('required'); // Joi message
    });

    it('should return 400 for invalid email format', async () => {
      const userData = {
        username: 'testuser',
        email: 'invalid-email',
        password: 'Password123!',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('email must be a valid email');
    });

    it('should return 400 for short password', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'short', // Too short
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('password') && expect(response.body.message).toContain('min');
    });
  });

  // Test for User Login
  describe('POST /api/v1/auth/login', () => {
    const loginCredentials = {
      email: 'login@example.com',
      password: 'PasswordSecure1!',
    };

    beforeEach(async () => {
      // Create a user to login with (password will be hashed in model)
      await User.create({
        username: 'loginuser',
        email: loginCredentials.email,
        password: loginCredentials.password, // Assuming pre-save hash
        name: 'Login User',
      });
    });

    it('should login an existing user successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginCredentials)
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe(loginCredentials.email);
      expect(response.body.accessToken).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();

      // Verify cookies
      const cookies = response.headers['set-cookie'] || [];
      expect(cookies.some((cookie) => cookie.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((cookie) => cookie.startsWith('refreshToken='))).toBe(true);

      // Verify refresh token in Redis
      const dbUser  = await User.findOne({ email: loginCredentials.email });
      const redisToken = await redisService.get(`refreshToken:${dbUser ._id}`);
      expect(redisToken).toBe(response.body.refreshToken);
    });

    it('should return 401 for invalid credentials (wrong password)', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: loginCredentials.email, password: 'WrongPassword!' })
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email or password.');
    });

    it('should return 401 for non-existent user', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'nonexistent@example.com', password: 'Password123!' })
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email or password.');
    });

    it('should return 400 for invalid login data (e.g., invalid email format)', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'notanemail', password: 'Password123!' })
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('email must be a valid email');
    });

    it('should return 400 for missing password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: loginCredentials.email })
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('password') && expect(response.body.message).toContain('required');
    });
  });

  // Test for Get Current User (Protected)
  describe('GET /api/v1/auth/getme', () => {
    let token;
    let userId;
    let cookies;

    beforeEach(async () => {
      // Register a user to get tokens
      const userData = {
        username: 'getmeuser',
        email: 'getme@example.com',
        password: 'PasswordGetMe1!',
        name: 'GetMe User',
      };
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      token = registerResponse.body.accessToken;
      userId = registerResponse.body.data._id;
      cookies = registerResponse.headers['set-cookie'] || [];
    });

    it('should return user details for a logged-in user', async () => {
      const response = await request(app)
        .get('/api/v1/auth/getme')
        .set('Cookie', cookies) // Pass all cookies
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe('getme@example.com');
      expect(response.body.data._id).toBe(userId);
      expect(response.body.data).not.toHaveProperty('password');
    });

    it('should return 401 if no token is provided', async () => {
      const response = await request(app)
        .get('/api/v1/auth/getme')
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('not logged in'); // Match your auth middleware error
    });

    it('should return 401 if access token is invalid/expired', async () => {
      // Simulate invalid token by using a wrong one
      const response = await request(app)
        .get('/api/v1/auth/getme')
        .set('Cookie', 'accessToken=invalidtoken')
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('not logged in') || expect(response.body.message).toContain('invalid token');
    });
  });

  // Test for Generate Access Token (using refresh token)
  describe('POST /api/v1/auth/access-token', () => { // Assuming route is /access-token
    let refreshToken;
    let userId;
    let cookies;

    beforeEach(async () => {
      // Register a user to get refresh token
      const userData = {
        username: 'accesstokenuser',
        email: 'accesstoken@example.com',
        password: 'PasswordAccess1!',
      };
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      refreshToken = registerResponse.body.refreshToken;
      userId = registerResponse.body.data._id;
      cookies = registerResponse.headers['set-cookie'] || [];
    });

    it('should generate a new access token with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/access-token')
        .set('Cookie', cookies)
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.accessToken).toBeDefined();
      expect(response.body.accessToken).not.toBe(refreshToken); // New token

      // Verify new cookie is set
      const newCookies = response.headers['set-cookie'] || [];
      expect(newCookies.some((cookie) => cookie.startsWith('accessToken='))).toBe(true);
    });

    it('should return 401 if no refresh token provided', async () => {
      const response = await request(app)
        .post('/api/v1/auth/access-token')
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('No refresh token provided');
    });

    it('should return 401 if refresh token is invalid', async () => {
      const response = await request(app)
        .post('/api/v1/auth/access-token')
        .set('Cookie', 'refreshToken=invalidtoken')
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid refresh token'); // Assuming service error
    });

    // Note: Testing expiration requires mocking time or TTL; this simulates by deleting from Redis
    it('should return 401 if refresh token is expired (not in Redis)', async () => {
      // Delete from Redis to simulate expiration
      await redisService.del(`refreshToken:${userId}`);

      const response = await request(app)
        .post('/api/v1/auth/access-token')
        .set('Cookie', cookies)
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid refresh token');
    });
  });

  // Test for Google OAuth Callback (Post-Authentication)
  describe('GET /api/v1/auth/google/callback', () => { // Assuming route
    let mockUser ;

    beforeEach(async () => {
      mockUser  = await User.create({
        username: 'googleuser',
        email: 'google@example.com',
        name: 'Google User',
        // Google users might not have password
      });
    });

    // Note: In a full test, you'd mock Passport to set req.user. This tests the controller logic assuming req.user is set.
    it('should handle successful Google callback and set tokens', async () => {
      // Mock req.user in a way that your middleware sets it (this is simplified; use passport-mock in real tests)
      // For now, assuming the route directly calls the controller with req.user set
      // You'd need to simulate successful OAuth flow here (e.g., via a test route or mock)
      // Placeholder: Adjust this based on your OAuth setup
      const response = await request(app)
        .get('/api/v1/auth/google/callback')
        .expect('Content-Type', /json/)
        .expect(200); // You'd need to simulate successful OAuth

      // This test assumes you have a way to mock the OAuth flow. Placeholder assertions:
      expect(response.body.success).toBe(true);
      expect(response.body.user.email).toBe(mockUser .email);
      expect(response.body.accessToken).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();

      // Verify Redis
      const redisToken = await redisService.get(`refreshToken:${mockUser ._id}`);
      expect(redisToken).toBeDefined();
    });

    it('should return 401 if no user from OAuth', async () => {
      // Simulate failed auth (no req.user)
      const response = await request(app)
        .get('/api/v1/auth/google/callback')
        .expect('Content-Type', /json/)
        .expect(401); // Adjust if your OAuth failure route differs

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Authentication failed');
    });
  });

  // Test for Logout
  describe('POST /api/v1/auth/logout', () => { // Assuming route
    let cookies;
    let userId;

    beforeEach(async () => {
      // Login to get cookies and userId
      const loginData = {
        email: 'logout@example.com',
        password: 'PasswordLogout1!',
      };
      await User.create({
        username: 'logoutuser',
        email: loginData.email,
        password: loginData.password,
      });

      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData);

      cookies = loginResponse.headers['set-cookie'] || [];
      userId = loginResponse.body.data._id;
    });

    it('should logout user successfully and clear cookies', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set('Cookie', cookies)
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Logged out successfully');

      // Verify cookies are cleared (set-cookie with maxAge=0 or expires in past)
           const accessCookie = setCookies.find((cookie) => cookie.startsWith('accessToken='));
      const refreshCookie = setCookies.find((cookie) => cookie.startsWith('refreshToken='));
      expect(accessCookie).toBeDefined();
      expect(refreshCookie).toBeDefined();
      // Cookies cleared usually have 'Expires=Thu, 01 Jan 1970 00:00:00 GMT' or 'Max-Age=0'
      expect(accessCookie).toMatch(/(Expires=Thu, 01 Jan 1970 00:00:00 GMT|Max-Age=0)/);
      expect(refreshCookie).toMatch(/(Expires=Thu, 01 Jan 1970 00:00:00 GMT|Max-Age=0)/);

      // Verify refresh token removed from Redis
      const redisToken = await redisService.get(`refreshToken:${userId}`);
      expect(redisToken).toBeNull();
    });

    it('should return 401 if user is not authenticated', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('not logged in');
    });
  });

  // Test for Verify Email (send verification email)
  describe('POST /api/v1/auth/verify-email', () => {
    it('should send verification email for valid email', async () => {
      const email = 'verify@example.com';

      // Mock userService.generateVerificationToken to return a dummy token
      jest.spyOn(userService, 'generateVerificationToken').mockResolvedValue('dummy-token');

      const response = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({ email })
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Verification email sent');
      expect(userService.generateVerificationToken).toHaveBeenCalledWith({ email });
      expect(mockedSendVerificationEmail).toHaveBeenCalledWith(
        email,
        expect.stringContaining('token=dummy-token')
      );

      // Restore mock
      userService.generateVerificationToken.mockRestore();
    });

    it('should return 400 if email is missing', async () => {
      const response = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({})
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('email') && expect(response.body.message).toContain('required');
    });

    it('should return 400 for invalid email format', async () => {
      const response = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({ email: 'invalid-email' })
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('email must be a valid email');
    });
  });

  // Test for Verify Email Token (email verification)
  describe('GET /api/v1/auth/verify-email', () => {
    it('should verify email with valid token', async () => {
      // Mock userService.verifyEmail to return a user object
      const mockUser  = {
        _id: 'user-id',
        email: 'verified@example.com',
        username: 'verifieduser',
      };
      jest.spyOn(userService, 'verifyEmail').mockResolvedValue(mockUser );

      const response = await request(app)
        .get('/api/v1/auth/verify-email')
        .query({ token: 'valid-token' })
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Email verified successfully');
      expect(response.body.user).toEqual(mockUser );
      expect(userService.verifyEmail).toHaveBeenCalledWith('valid-token');

      userService.verifyEmail.mockRestore();
    });

    it('should return 400 if token is missing', async () => {
      const response = await request(app)
        .get('/api/v1/auth/verify-email')
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Token is required');
    });

    it('should return 401 for invalid or expired token', async () => {
      jest.spyOn(userService, 'verifyEmail').mockResolvedValue(null);

      const response = await request(app)
        .get('/api/v1/auth/verify-email')
        .query({ token: 'invalid-or-expired-token' })
        .expect('Content-Type', /json/)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid or expired token');

      userService.verifyEmail.mockRestore();
    });
  });
});
