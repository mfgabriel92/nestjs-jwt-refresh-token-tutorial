import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { JwtStrategy, RefreshTokenStrategy } from './strategies/index';
import { AuthService } from './auth.service';

@Module({
  controllers: [AuthController],
  providers: [JwtStrategy, JwtService, RefreshTokenStrategy, AuthService],
})
export class AuthModule {}
