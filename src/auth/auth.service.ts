import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';

import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { envs } from 'src/config';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Connected to the MongoDB database');
  }

  async singJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.singJwt(user),
      };
    } catch {
      throw new RpcException({
        status: 401,
        message: 'Unauthorized',
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      delete newUser.password;

      return {
        user: newUser,
        token: await this.singJwt(newUser),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/password not valid',
        });
      }

      const isValid = bcrypt.compareSync(password, user.password);

      if (!isValid) {
        throw new RpcException({
          status: 400,
          message: 'User/password not valid',
        });
      }

      delete user.password;

      return {
        user,
        token: await this.singJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
