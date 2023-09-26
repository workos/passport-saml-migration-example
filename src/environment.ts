export const isProduction = process.env.NODE_ENV === "production";

export const fromEnvOrThrow = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Environment variable "${key}" must be set.`);
  }

  return value;
};
