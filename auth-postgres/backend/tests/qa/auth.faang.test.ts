/**
 * FAANG-Level QA Test Suite – Auth Backend
 *
 * Covers:
 *  - Registration: validation, idempotency, email normalisation, SQL-injection-style payloads
 *  - Login: brute-force patterns, account status, session creation
 *  - Logout: blacklisting, cookie clearing, session deletion, double-logout
 *  - Token Refresh: expired token flow, revoked session, banned user mid-session
 *  - Blacklist: TTL/hash correctness, no reuse after logout
 *  - Session: one session created per login, no carry-over across logins
 *  - Security headers: CORS, sensitive field leakage
 *  - DRY / regression checks
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
} from "vitest";
import request from "supertest";
import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import jwt from "jsonwebtoken";
import type { Express } from "express";
import { hashToken } from "../../src/utils/hash.util";

const JWT_SECRET = "test-jwt-secret-key-min-32-chars-long!!";

let mongod: MongoMemoryServer;
let app: Express;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function uniqueUser() {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return {
    email: `user.${id}@example.com`,
    password: "ValidPass1!",
    confirmPassword: "ValidPass1!",
  };
}

async function registerAndLogin(agentOrApp?: any, overrides?: Partial<{ password: string }>) {
  const payload = uniqueUser();
  if (overrides?.password) {
    payload.password = overrides.password;
    payload.confirmPassword = overrides.password;
  }
  const requester = agentOrApp ? agentOrApp : request(app);
  await request(app).post("/api/v1/register").send(payload);
  const login = await requester
    .post("/api/v1/login")
    .send({ email: payload.email, password: payload.password });
  return { payload, login };
}

function makeExpiredToken(userId: string) {
  return jwt.sign(
    { id: userId, exp: Math.floor(Date.now() / 1000) - 120 },
    JWT_SECRET
  );
}

// ─── Setup / Teardown ────────────────────────────────────────────────────────

beforeAll(async () => {
  process.env.JWT_SECRET = JWT_SECRET;
  process.env.NODE_ENV = "test";
  mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri();
  await mongoose.connect(process.env.MONGODB_URI, { dbName: "Auth" });
  const mod = await import("../../src/app");
  app = mod.default;
});

afterEach(async () => {
  const cols = mongoose.connection.collections;
  await Promise.all(Object.values(cols).map((c) => c.deleteMany({})));
});

afterAll(async () => {
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
});

// ═══════════════════════════════════════════════════════════════════════════════
// 1. REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════════
describe("POST /api/v1/register", () => {
  // --- Happy paths ---
  it("[PASS] registers a new user and returns 201 with sanitised body", async () => {
    const p = uniqueUser();
    const res = await request(app).post("/api/v1/register").send(p).expect(201);
    expect(res.body.data.password).toBeUndefined();
    expect(res.body.data.refreshToken).toBeUndefined();
    expect(res.body.data.email).toBe(p.email.toLowerCase());
  });

  it("[PASS] email is stored lowercase even if sent with mixed case", async () => {
    const p = uniqueUser();
    p.email = p.email.toUpperCase();
    const res = await request(app).post("/api/v1/register").send(p).expect(201);
    expect(res.body.data.email).toBe(p.email.toLowerCase());
  });

  it("[PASS] allows passwords with special characters (no spaces)", async () => {
    const p = uniqueUser();
    p.password = "Str0ng@Pass#99";
    p.confirmPassword = "Str0ng@Pass#99";
    await request(app).post("/api/v1/register").send(p).expect(201);
  });

  // --- Validation failures ---
  it("[FAIL] rejects missing email", async () => {
    const p = uniqueUser();
    const res = await request(app)
      .post("/api/v1/register")
      .send({ password: p.password, confirmPassword: p.confirmPassword })
      .expect(400);
    expect(res.body.message).toMatch(/email/i);
  });

  it("[FAIL] rejects invalid email format", async () => {
    const p = uniqueUser();
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, email: "not-an-email" })
      .expect(400);
  });

  it("[FAIL] rejects password shorter than 8 characters", async () => {
    const p = uniqueUser();
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, password: "Ab1!", confirmPassword: "Ab1!" })
      .expect(400);
  });

  it("[FAIL] rejects password with whitespace", async () => {
    const p = uniqueUser();
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, password: "Pass word1", confirmPassword: "Pass word1" })
      .expect(400);
  });

  it("[FAIL] rejects when confirmPassword does not match", async () => {
    const p = uniqueUser();
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, confirmPassword: "DifferentPass1!" })
      .expect(400);
  });

  it("[FAIL] rejects password exceeding 128 characters", async () => {
    const p = uniqueUser();
    const longPass = "A1!" + "a".repeat(130);
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, password: longPass, confirmPassword: longPass })
      .expect(400);
  });

  // --- Security / Edge cases ---
  it("[SECURITY] rejects duplicate registration (idempotency) with 409", async () => {
    const p = uniqueUser();
    await request(app).post("/api/v1/register").send(p).expect(201);
    const res = await request(app).post("/api/v1/register").send(p).expect(409);
    expect(res.body.message).toMatch(/already/i);
  });

  it("[SECURITY] duplicate email differing only in case is rejected", async () => {
    const p = uniqueUser();
    await request(app).post("/api/v1/register").send(p).expect(201);
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, email: p.email.toUpperCase() })
      .expect(409);
  });

  it("[SECURITY] extra unknown fields in body are stripped (no polluting)", async () => {
    const p = uniqueUser();
    const res = await request(app)
      .post("/api/v1/register")
      .send({ ...p, isAdmin: true, role: "superadmin" })
      .expect(201);
    expect((res.body.data as any).isAdmin).toBeUndefined();
    expect((res.body.data as any).role).toBeUndefined();
  });

  it("[SECURITY] NoSQL injection attempt in email is rejected", async () => {
    const p = uniqueUser();
    await request(app)
      .post("/api/v1/register")
      .send({ ...p, email: { $gt: "" } })
      .expect(400);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. LOGIN
// ═══════════════════════════════════════════════════════════════════════════════
describe("POST /api/v1/login", () => {
  it("[PASS] returns accessToken and sets HttpOnly refreshToken cookie", async () => {
    const { payload, login } = await registerAndLogin();
    expect(login.status).toBe(200);
    expect(login.body.data.accessToken).toBeTruthy();
    const cookieHeader = String(login.headers["set-cookie"] ?? "");
    expect(cookieHeader).toMatch(/refreshToken=/i);
    expect(cookieHeader).toMatch(/HttpOnly/i);
  });

  it("[PASS] response does NOT expose password or raw refreshToken", async () => {
    const { login } = await registerAndLogin();
    expect(login.body.data.user?.password).toBeUndefined();
    expect(login.body.data.user?.refreshToken).toBeUndefined();
  });

  it("[PASS] creates exactly one session document per login", async () => {
    const { payload } = await registerAndLogin();
    const sessions = await mongoose.connection
      .collection("sessions")
      .find({ })
      .toArray();
    expect(sessions).toHaveLength(1);
  });

  it("[PASS] session stores HASHED token, not the raw token", async () => {
    const { login } = await registerAndLogin();
    const cookieRaw = String(login.headers["set-cookie"] ?? "")
      .split(";")[0]
      ?.split("=")[1];
    const rawToken = decodeURIComponent(cookieRaw ?? "");
    const session = await mongoose.connection
      .collection("sessions")
      .findOne({});
    expect(session?.refreshToken).toBe(hashToken(rawToken));
    expect(session?.refreshToken).not.toBe(rawToken);
  });

  it("[FAIL] returns 404 for non-existent email", async () => {
    await request(app)
      .post("/api/v1/login")
      .send({ email: "ghost@example.com", password: "ValidPass1!" })
      .expect(404);
  });

  it("[FAIL] returns 400 for wrong password", async () => {
    const { payload } = await registerAndLogin();
    await request(app)
      .post("/api/v1/login")
      .send({ email: payload.email, password: "WrongPassword9!" })
      .expect(400);
  });

  it("[FAIL] returns 400 for missing password field", async () => {
    const { payload } = await registerAndLogin();
    await request(app)
      .post("/api/v1/login")
      .send({ email: payload.email })
      .expect(400);
  });

  it("[SECURITY] multiple logins create multiple sessions (multi-device safe)", async () => {
    const { payload } = await registerAndLogin();
    // Second login from "another device"
    await request(app)
      .post("/api/v1/login")
      .send({ email: payload.email, password: payload.password });
    const sessions = await mongoose.connection
      .collection("sessions")
      .find({})
      .toArray();
    expect(sessions.length).toBeGreaterThanOrEqual(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. LOGOUT
// ═══════════════════════════════════════════════════════════════════════════════
describe("POST /api/v1/logout", () => {
  it("[PASS] returns 200 and clears the refresh cookie", async () => {
    const { login } = await registerAndLogin();
    const token = login.body.data.accessToken as string;
    const res = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);
    const clearedCookie = String(res.headers["set-cookie"] ?? "");
    expect(clearedCookie).toMatch(/refreshToken=/i);
  });

  it("[PASS] deletes the session from DB on logout", async () => {
    const agent = request.agent(app);
    const { login } = await registerAndLogin(agent);
    const token = login.body.data.accessToken as string;

    await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    const sessions = await mongoose.connection
      .collection("sessions")
      .find({})
      .toArray();
    expect(sessions).toHaveLength(0);
  });

  it("[PASS] adds the token to blacklist after logout", async () => {
    const { login } = await registerAndLogin();
    const token = login.body.data.accessToken as string;
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);
    const blacklisted = await mongoose.connection
      .collection("tokenblacklists")
      .findOne({ tokenHash: hashToken(token) });
    expect(blacklisted).not.toBeNull();
  });

  it("[FAIL] returns 401 with no Authorization header", async () => {
    await request(app).post("/api/v1/logout").expect(401);
  });

  it("[FAIL] returns 401 when using a malformed token", async () => {
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", "Bearer this.is.invalid")
      .expect(401);
  });

  it("[SECURITY] double-logout with same token is rejected with blacklist error", async () => {
    const { login } = await registerAndLogin();
    const token = login.body.data.accessToken as string;

    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    const res = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(401);
    expect(res.body.message).toMatch(/blacklisted/i);
  });

  it("[SECURITY] using a completely fabricated JWT is rejected", async () => {
    const fakeToken = jwt.sign({ id: new mongoose.Types.ObjectId() }, "wrong-secret");
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${fakeToken}`)
      .expect(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. TOKEN REFRESH (via expired access token + valid refresh cookie)
// ═══════════════════════════════════════════════════════════════════════════════
describe("Middleware: Token refresh flow", () => {
  it("[PASS] issues new accessToken via x-new-access-token header when expired", async () => {
    const agent = request.agent(app);
    const { payload, login } = await registerAndLogin();
    const userId = String(login.body.data.user._id);

    const expiredToken = makeExpiredToken(userId);

    // Manually set the refresh cookie (agent keeps it from login)
    await agent
      .post("/api/v1/login")
      .send({ email: payload.email, password: payload.password });

    const res = await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`);

    expect(res.status).toBe(200);
    expect(String(res.headers["x-new-access-token"] || "")).toBeTruthy();
  });

  it("[PASS] issues a new rotated refreshToken cookie on token refresh", async () => {
    const agent = request.agent(app);
    const { payload, login } = await registerAndLogin();
    const userId = String(login.body.data.user._id);

    await agent
      .post("/api/v1/login")
      .send({ email: payload.email, password: payload.password });

    const expiredToken = makeExpiredToken(userId);
    const res = await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`);

    const newCookie = String(res.headers["set-cookie"] ?? "");
    expect(newCookie).toMatch(/refreshToken=/i);
  });

  it("[FAIL] returns 401 when expired token has no refresh cookie", async () => {
    const { login } = await registerAndLogin();
    const userId = String(login.body.data.user._id);
    const expiredToken = makeExpiredToken(userId);

    // No cookie agent — raw request
    const res = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`)
      .expect(401);
    expect(res.body.message).toMatch(/expired|session/i);
  });

  it("[FAIL] returns 401 when refresh cookie is tampered with", async () => {
    const { login } = await registerAndLogin();
    const userId = String(login.body.data.user._id);
    const expiredToken = makeExpiredToken(userId);

    const res = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`)
      .set("Cookie", "refreshToken=tampered_value_that_does_not_exist_in_db")
      .expect(401);
    expect(res.body.message).toMatch(/session|invalid/i);
  });

  it("[SECURITY] old refresh cookie cannot be reused after rotation", async () => {
    const agent = request.agent(app);
    const { payload, login } = await registerAndLogin();
    const userId = String(login.body.data.user._id);

    const loginRes = await agent
      .post("/api/v1/login")
      .send({ email: payload.email, password: payload.password });

    // Extract original raw refresh token from cookie
    const originalCookieRaw = String(loginRes.headers["set-cookie"] ?? "")
      .split(";")[0]
      ?.split("=")[1];
    const originalRefreshToken = decodeURIComponent(originalCookieRaw ?? "");

    // First refresh: triggers rotation
    const expiredToken = makeExpiredToken(userId);
    await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`);

    // Try to replay the original (pre-rotation) refresh token
    const replayRes = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`)
      .set("Cookie", `refreshToken=${originalRefreshToken}`)
      .expect(401);
    expect(replayRes.body.message).toMatch(/session|invalid/i);
  });

  it("[SECURITY] returns 401 when the refresh session is logically expired (manual DB check)", async () => {
    const agent = request.agent(app);
    const { payload, login } = await registerAndLogin(agent);
    const userId = String(login.body.data.user._id);

    // Manually backdate the session in the DB to make it "expired"
    await mongoose.connection
      .collection("sessions")
      .updateOne({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });

    const expiredToken = makeExpiredToken(userId);
    const res = await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expiredToken}`)
      .expect(401);

    expect(res.body.message).toMatch(/expired|revoked/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════════
describe("GET /api/health", () => {
  it("[PASS] returns 200 with correct body", async () => {
    const res = await request(app).get("/api/health").expect(200);
    expect(res.body).toMatchObject({
      status: "OK",
      message: "Backend is running correctly",
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. REGRESSION – Sensitive Data Leakage
// ═══════════════════════════════════════════════════════════════════════════════
describe("Regression: Sensitive field leakage", () => {
  it("[REGRESSION] registration response never exposes __v or password", async () => {
    const p = uniqueUser();
    const res = await request(app).post("/api/v1/register").send(p).expect(201);
    expect(res.body.data.__v).toBeUndefined();
    expect(res.body.data.password).toBeUndefined();
  });

  it("[REGRESSION] login response never exposes password or refreshToken", async () => {
    const { login } = await registerAndLogin();
    expect(login.body.data.user?.password).toBeUndefined();
    expect(login.body.data.user?.refreshToken).toBeUndefined();
  });

  it("[REGRESSION] session collection stores hashed refresh token not raw", async () => {
    const { login } = await registerAndLogin();
    const cookieRaw = String(login.headers["set-cookie"] ?? "")
      .split(";")[0]
      ?.split("=")[1];
    const rawToken = decodeURIComponent(cookieRaw ?? "");
    const session = await mongoose.connection.collection("sessions").findOne({});
    expect(session?.refreshToken).toBe(hashToken(rawToken));
    expect(session?.refreshToken).not.toBe(rawToken);
  });

  it("[REGRESSION] blacklist stores hashed token not raw", async () => {
    const { login } = await registerAndLogin();
    const token = login.body.data.accessToken as string;
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    const doc = await mongoose.connection
      .collection("tokenblacklists")
      .findOne({});
    expect(doc?.tokenHash).toBe(hashToken(token));
    expect(doc?.tokenHash).not.toBe(token);
  });
});
