import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  // DATABASE_URL: string;
  NATS_SERVERS: string[];

  JWT_SECRET: string;
}

const envSchema = joi
  .object({
    PORT: joi.number().required(),
    // DATABASE_URL: joi.string().required(),
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    JWT_SECRET: joi.string().required(),
  })
  .unknown(true);

const { error, value } = envSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  // databaseUrl: envVars.DATABASE_URL,
  natsServer: envVars.NATS_SERVERS,
  jwtSecret: envVars.JWT_SECRET,
};
