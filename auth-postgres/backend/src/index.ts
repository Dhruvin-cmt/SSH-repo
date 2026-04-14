import "dotenv/config";
import connectDB from "./config/database";
import app from "./app";

function assertJwtSecret(): void {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    console.error(
      "FATAL: JWT_SECRET must be set in the environment and be at least 32 characters long."
    );
    process.exit(1);
  }
}

async function start(): Promise<void> {
  assertJwtSecret();
  await connectDB();
  const port = Number(process.env.PORT) || 5001;
  app.listen(port, () => {
    console.log(
      `Server is running on port ${port} in ${process.env.NODE_ENV || "development"} mode`
    );
  });
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});
