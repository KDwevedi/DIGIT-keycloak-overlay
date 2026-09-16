import { defineConfig } from "vitest/config";

/** Tests for the retired generic Keycloak-to-DIGIT proxy runtime. */
export default defineConfig({
  test: {
    globals: true,
    testTimeout: 15000,
    hookTimeout: 30000,
    globalSetup: "./tests/setup.ts",
    setupFiles: ["./tests/worker-setup.ts"],
    include: ["tests/**/*.test.ts"],
    exclude: [
      "tests/integration/**",
      "tests/unit/cache.test.ts",
      "tests/unit/keycloak-admin.test.ts",
      "tests/unit/managed-digit-users.test.ts",
      "tests/e2e/identity-bff.test.ts",
      "tests/e2e/onboarding-worker.test.ts",
    ],
    pool: "forks",
    fileParallelism: false,
    sequence: { files: "list" },
  },
});
