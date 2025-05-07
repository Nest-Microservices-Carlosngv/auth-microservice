import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config/envs';
import { PrismaClient } from 'generated/prisma';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  
  private readonly logger = new Logger('AuthService');

  constructor(
    private readonly jwtService: JwtService,
  ) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected')
  }


  async signJWT( payload: JWTPayload ) {
    return await this.jwtService.signAsync( payload );
  }

  async verifyToken( token: string ) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify( token, {
        secret: envs.jwtSecret,
      } );


      return {
        user,
        token: await this.signJWT( user ),
      }
    } catch (error) {
      console.log( { error } )
      throw new RpcException({
        status: 400,
        message: 'Invalid token',
      });
    }
  }

  async registerUser( registerUserDto: RegisterUserDto ) {

    const { name, email, password } = registerUserDto;

    try {
      
      const user = await this.user.findFirst({
        where: { email }
      });

      if( user )
          throw new RpcException({ status: 400, message: 'User already exists' });
      
      // TODO: hash password
      const { password: __, ...rest } = await this.user.create({
        data: { 
          email, 
          password: bcrypt.hashSync( password, 10 ), 
          name, 
        },
      });


      return {
        user: rest,
        token: await this.signJWT( rest ),
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }

  }

  async loginUser( loginUserDto: LoginUserDto ) {

    try {
      
      const user = await this.user.findFirst({
        where: { email: loginUserDto.email }
      });

      if( !user )
          throw new RpcException({ status: 404, message: 'User does not exists' });
    
      const isPasswordValid = bcrypt.compareSync( loginUserDto.password, user.password );
      
      if( !isPasswordValid )
        throw new RpcException({ status: 400, message: 'User/Password not valid' });


      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT( rest ),
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }

  }

}