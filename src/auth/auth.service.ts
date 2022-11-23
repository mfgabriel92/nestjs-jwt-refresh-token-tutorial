import { PrismaService } from '@database/prisma.service';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as argon from 'argon2';
import { SignUpDto } from './dtos/index';
import { SignInDto } from './dtos/sign-in.dto';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async signUp(data: SignUpDto): Promise<Tokens> {
    const hashedPassword = await this.hash(data.password);
    const user = await this.prisma.user.create({
      data: {
        name: data.name,
        email: data.email,
        password: hashedPassword,
        refreshToken: '',
      },
    });

    return await this.getAccessTokenAndRefreshToken(user);
  }

  async signIn(data: SignInDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (!user) {
      throw new ForbiddenException('E-mail or password do not match');
    }

    const passwordsMatch = await argon.verify(user.password, data.password);
    if (!passwordsMatch) {
      throw new ForbiddenException('E-mail or password do not match');
    }

    return await this.getAccessTokenAndRefreshToken(user);
  }

  async logout(userId: string) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        refreshToken: {
          not: '',
        },
      },
      data: {
        refreshToken: '',
      },
    });
  }

  async refreshToken(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('You may not perform this action');
    }

    const refreshTokensMatch = await argon.verify(
      user.refreshToken,
      refreshToken,
    );

    if (!refreshTokensMatch) {
      throw new ForbiddenException('You may not perform this action');
    }

    return await this.getAccessTokenAndRefreshToken(user);
  }

  private async hash(data: string) {
    return argon.hash(data);
  }

  private async getAccessTokenAndRefreshToken(user: User): Promise<Tokens> {
    const tokens = await this.generateTokens(user.id, user.name, user.email);
    const { accessToken, refreshToken } = tokens;

    await this.updateRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken };
  }

  private async generateTokens(
    userId: string,
    name: string,
    email: string,
  ): Promise<Tokens> {
    const payload = {
      sub: userId,
      name,
      email,
    };

    const [accessToken, refreshToken] = await Promise.all([
      await this.jwt.signAsync(payload, {
        secret: process.env.JWT_SECRET,
        expiresIn: 60 * 15,
      }),
      await this.jwt.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_SECRET,
        expiresIn: 60 * 60 * 24 * 7,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hash(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: { refreshToken: hashedRefreshToken },
    });
  }
}
