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
  const collections = mongoose.connection.collections;
  for (const collectionName of Object.keys(collections)) {
    const col = collections[collectionName];
    if (col) await col.deleteMany({});
  }
});

afterAll(async () => {
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
});

function registerPayload() {
  const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return {
    email: `user.${id}@example.com`,
    password: "Password1",
    confirmPassword: "Password1",
  };
}

describe("GET /api/health", () => {
  it("returns 200 and status OK", async () => {
    const res = await request(app).get("/api/health").expect(200);
    expect(res.body).toMatchObject({
      status: "OK",
      message: "Backend is running correctly",
    });
  });
});

describe("POST /api/v1/register", () => {
  it("rejects invalid email with 400", async () => {
    const res = await request(app)
      .post("/api/v1/register")
      .send({
        email: "not-an-email",
        password: "Password1",
        confirmPassword: "Password1",
      })
      .expect(400);
    expect(String(res.body.message || "")).toMatch(/email|valid/i);
  });

  it("rejects weak/mismatch confirmation with 400", async () => {
    const body = registerPayload();
    const res = await request(app)
      .post("/api/v1/register")
      .send({
        ...body,
        confirmPassword: "Password2",
      })
      .expect(400);
    expect(String(res.body.message || "").length).toBeGreaterThan(0);
  });

  it("returns 201, omits password from JSON, normalizes email", async () => {
    const body = registerPayload();
    const res = await request(app).post("/api/v1/register").send(body).expect(201);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.password).toBeUndefined();
    expect(res.body.data.refreshToken).toBeUndefined();
    expect(res.body.data.email).toBe(body.email.toLowerCase());
  });

  it("returns 409 when user already exists", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body).expect(201);
    const again = await request(app).post("/api/v1/register").send(body).expect(409);
    expect(String(again.body.message || "")).toMatch(/already/i);
  });

  it("allows passwords with common symbols (no spaces)", async () => {
    const body = registerPayload();
    const res = await request(app)
      .post("/api/v1/register")
      .send({
        ...body,
        password: "Password1!",
        confirmPassword: "Password1!",
      });
    expect(res.status).toBe(201);
  });

  it("rejects passwords that contain whitespace", async () => {
    const body = registerPayload();
    const res = await request(app).post("/api/v1/register").send({
      ...body,
      password: "Pass word1",
      confirmPassword: "Pass word1",
    });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/v1/login", () => {
  it("returns 404 for unknown user", async () => {
    await request(app)
      .post("/api/v1/login")
      .send({ email: "nobody@example.com", password: "Password1" })
      .expect(404);
  });

  it("returns 400 for wrong password", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    await request(app)
      .post("/api/v1/login")
      .send({ email: body.email, password: "WrongPass1" })
      .expect(400);
  });

  it("returns accessToken and sets refresh cookie on success", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    const res = await request(app)
      .post("/api/v1/login")
      .send({ email: body.email, password: body.password })
      .expect(200);
    expect(res.body.data.accessToken).toBeTruthy();
    const setCookie = res.headers["set-cookie"];
    expect(setCookie).toBeDefined();
    expect(String(setCookie)).toMatch(/refreshToken=/i);
  });
});

describe("POST /api/v1/logout", () => {
  it("returns 401 without Bearer token", async () => {
    await request(app).post("/api/v1/logout").expect(401);
  });

  it("returns 200 with valid access token", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    const login = await request(app)
      .post("/api/v1/login")
      .send({ email: body.email, password: body.password })
      .expect(200);
    const token = login.body.data.accessToken as string;
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);
  });

  it("rejects the same access token after successful logout", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    const login = await request(app)
      .post("/api/v1/login")
      .send({ email: body.email, password: body.password })
      .expect(200);
    const token = login.body.data.accessToken as string;

    // First logout works
    await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    // Second use of same token should fail
    const res = await request(app)
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${token}`)
      .expect(401);
    expect(res.body.message).toMatch(/blacklisted/i);
  });

  it("refreshes access token when expired but refresh cookie is valid", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    const agent = request.agent(app);
    const login = await agent
      .post("/api/v1/login")
      .send({ email: body.email, password: body.password })
      .expect(200);
    const userId = String(login.body.data.user._id);
    const expired = jwt.sign(
      { id: userId, exp: Math.floor(Date.now() / 1000) - 60 },
      JWT_SECRET
    );
    const res = await agent
      .post("/api/v1/logout")
      .set("Authorization", `Bearer ${expired}`);
    expect(res.status).toBe(200);
    expect(String(res.headers["x-new-access-token"] || "")).toBeTruthy();
  });
});

describe("Regression: Mongo user document", () => {
  it("stores SHA-256 hash of refresh token; cookie sets raw token", async () => {
    const body = registerPayload();
    await request(app).post("/api/v1/register").send(body);
    const login = await request(app)
      .post("/api/v1/login")
      .send({ email: body.email, password: body.password })
      .expect(200);
    const rawDoc = await mongoose.connection.collection("users").findOne({
      email: body.email.toLowerCase(),
    });
    expect(rawDoc?.refreshToken).toBeTruthy();
    const cookiePair = String(login.headers["set-cookie"] || "")
      .split(";")[0]
      ?.trim();
    const cookieVal = cookiePair?.split("=")[1];
    expect(cookieVal).toBeTruthy();
    expect(hashToken(decodeURIComponent(cookieVal as string))).toBe(rawDoc?.refreshToken);
    expect(cookieVal).not.toBe(rawDoc?.refreshToken);
  });
});
